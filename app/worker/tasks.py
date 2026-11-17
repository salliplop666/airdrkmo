import logging
import uuid

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, select, update

from app.core.audit import log_event
from app.core.config import settings
from app.core.ratelimit import redis_client
from app.core.security import utcnow
from app.core.ssrf import UnsafeTargetError, validate_public_url
from app.db.models import Client, Finding, Scan, Target
from app.db.session import SessionLocal, set_tenant
from app.scanner.base import ScanRequest
from app.scanner.zap import ZapScanner
from app.services import reports as report_service
from app.services.email import send_smtp
from app.worker.celery_app import celery_app

log = logging.getLogger(__name__)
MAX_S = settings.scan_max_minutes * 60


def cancel_key(scan_id) -> str:
    return f"scan:cancel:{scan_id}"


@celery_app.task(name="email.send", autoretry_for=(OSError,), retry_backoff=True, max_retries=3)
def send_email(to: str, subject: str, body: str) -> None:
    send_smtp(to, subject, body)


@celery_app.task(name="scans.run", soft_time_limit=MAX_S + 300, time_limit=MAX_S + 600)
def run_scan(scan_id: str, org_id: str) -> str:
    sid, r = uuid.UUID(scan_id), redis_client()
    scanner = None
    with SessionLocal() as db:
        set_tenant(db, org_id)
        # Reclamo atómico: si Celery reentrega la tarea, solo un worker pasa de queued → running.
        claimed = db.execute(update(Scan).where(Scan.id == sid, Scan.status == "queued")
                             .values(status="running", started_at=func.now())).rowcount
        db.commit()
        if not claimed:
            return "skipped"
        scan = db.get(Scan, sid)
        lock = r.lock(f"scanlock:{scan.target_id}", timeout=MAX_S + 600, blocking=False)
        got_lock = lock.acquire()
        try:
            if not got_lock:
                raise RuntimeError("busy")
            target, client = db.get(Target, scan.target_id), db.get(Client, scan.client_id)
            # Re-validación justo antes de escanear (el DNS o el contrato pueden haber cambiado).
            v = validate_public_url(scan.target_url, allowed_ports=settings.allowed_ports)
            today = utcnow().date()
            if client.status != "active" or not (client.contract_start <= today <= client.contract_end):
                raise UnsafeTargetError("contract_inactive", "El contrato del cliente no está vigente.")
            scan.resolved_ips = list(v.resolved_ips)
            log_event(db, action="scan.started", org_id=scan.org_id, actor_id=scan.requested_by,
                      resource_type="scan", resource_id=scan.id,
                      details={"url": v.url, "mode": scan.mode, "resolved_ips": list(v.resolved_ips)})
            db.commit()

            scanner = ZapScanner()
            outcome = scanner.run(
                ScanRequest(scan_id=scan_id, url=v.url, hostname=v.hostname, port=v.port,
                            include_subdomains=target.include_subdomains, mode=scan.mode),
                should_cancel=lambda: bool(r.exists(cancel_key(scan_id))))
            seen = set()
            for f in outcome.findings:
                fp = f.fingerprint()
                if fp in seen:
                    continue
                seen.add(fp)
                db.add(Finding(org_id=scan.org_id, scan_id=scan.id, rule_id=f.rule_id, title=f.title,
                               severity=f.severity, confidence=f.confidence, url=f.url, method=f.method,
                               param=f.param, cwe_id=f.cwe_id, description=f.description,
                               solution=f.solution, reference=f.reference, evidence=f.evidence,
                               fingerprint=fp))
            by_sev: dict[str, int] = {}
            for f in outcome.findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            scan.stats = {**outcome.stats, "findings_by_severity": by_sev}
            scan.status = "cancelled" if outcome.cancelled else "completed"
            scan.finished_at = utcnow()
            log_event(db, action=f"scan.{scan.status}", org_id=scan.org_id, actor_id=scan.requested_by,
                      resource_type="scan", resource_id=scan.id, details={"findings": by_sev})
            db.commit()
            if scan.status == "completed":
                generate_report.delay(scan_id, org_id)
            return scan.status
        except Exception as exc:          # incluye SoftTimeLimitExceeded
            db.rollback()
            scan = db.get(Scan, sid)
            if isinstance(exc, UnsafeTargetError):
                msg, reason = str(exc), exc.code
            elif isinstance(exc, SoftTimeLimitExceeded):
                msg, reason = "Tiempo máximo excedido.", "timeout"
            elif str(exc) == "busy":
                msg, reason = "Ya hay un escaneo en curso para este objetivo.", "target_busy"
            else:
                log.exception("scan %s failed", scan_id)       # detalle solo en logs del worker
                msg, reason = "Error interno del escáner.", "scanner_error"
            scan.status, scan.error, scan.finished_at = "failed", msg, utcnow()
            log_event(db, action="scan.failed", org_id=scan.org_id, actor_id=scan.requested_by,
                      resource_type="scan", resource_id=scan.id, details={"reason": reason})
            db.commit()
            return "failed"
        finally:
            if scanner:
                scanner.cleanup()
            if got_lock:
                try:
                    lock.release()
                except Exception:
                    pass
            r.delete(cancel_key(scan_id))


@celery_app.task(name="reports.generate")
def generate_report(scan_id: str, org_id: str) -> int:
    with SessionLocal() as db:
        set_tenant(db, org_id)
        scan = db.get(Scan, uuid.UUID(scan_id))
        reps = report_service.build_reports(db, scan)
        log_event(db, action="report.generated", org_id=scan.org_id, actor_id=scan.requested_by,
                  resource_type="scan", resource_id=scan.id, details={"formats": [x.format for x in reps]})
        db.commit()
        return len(reps)
