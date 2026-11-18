import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import get_client_or_404, get_current_user, get_db, require_role, visible_clients_query
from app.core.audit import log_event
from app.core.config import settings
from app.core.ratelimit import redis_client
from app.core.security import utcnow
from app.core.ssrf import UnsafeTargetError, validate_public_url
from app.db.models import Client, ConsentRecord, Finding, Report, Scan, Target, User
from app.services import reports as report_service
from app.services.consent import CONSENT_VERSION, consent_statement, statement_sha256
from app.services.targets import hostname_in_scope
from app.worker.tasks import cancel_key, run_scan

router = APIRouter(tags=["scans"])
auditor_only = require_role("auditor")     # separación de funciones: quien gestiona clientes no escanea


class ConsentIn(BaseModel):
    accepted: bool
    statement_version: str
    authorization_reference: str = Field(min_length=3, max_length=200)


class ScanCreate(BaseModel):
    client_id: uuid.UUID
    url: str = Field(max_length=2048)
    mode: Literal["passive", "active_safe"] = "passive"
    consent: ConsentIn


def _deny(db: Session, user: User, request: Request, status: int, reason: str, detail: str, **meta):
    """Los intentos denegados también quedan registrados (trazabilidad de quién intentó qué)."""
    log_event(db, action="scan.denied", org_id=user.org_id, actor_id=user.id, request=request,
              details={"reason": reason, **meta})
    db.commit()
    raise HTTPException(status, detail)


def _scan_out(s: Scan) -> dict:
    return {"id": s.id, "client_id": s.client_id, "target_url": s.target_url, "mode": s.mode,
            "status": s.status, "error": s.error, "stats": s.stats, "queued_at": s.queued_at,
            "started_at": s.started_at, "finished_at": s.finished_at, "requested_by": s.requested_by}


def _get_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    visible = visible_clients_query(user).with_only_columns(Client.id)
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id, Scan.client_id.in_(visible)))
    if not s:
        raise HTTPException(404, "Escaneo no encontrado")
    return s


@router.get("/scans/consent-statement")
def get_consent_statement(hostname: str, mode: Literal["passive", "active_safe"] = "passive",
                          _: User = Depends(auditor_only)):
    text = consent_statement(hostname.lower()[:253], mode)
    return {"version": CONSENT_VERSION, "text": text}


@router.post("/scans", status_code=202)
def create_scan(body: ScanCreate, request: Request, user: User = Depends(auditor_only),
                db: Session = Depends(get_db)):
    client = get_client_or_404(db, user, body.client_id)          # solo clientes asignados al auditor
    today = utcnow().date()
    if client.status != "active" or not (client.contract_start <= today <= client.contract_end):
        _deny(db, user, request, 403, "contract_inactive", "El contrato del cliente no está vigente.",
              client=str(client.id))
    try:                                                          # 1) SSRF / URL pública
        v = validate_public_url(body.url, allowed_ports=settings.allowed_ports)
    except UnsafeTargetError as e:
        _deny(db, user, request, 422, f"ssrf:{e.code}", str(e), client=str(client.id), url=body.url[:200])
    # 2) la URL debe caer dentro del alcance contratado de ESTE cliente
    targets = db.scalars(select(Target).where(Target.client_id == client.id)).all()
    target = next((t for t in targets if hostname_in_scope(v.hostname, t)), None)
    if target is None:
        _deny(db, user, request, 403, "out_of_scope", "La URL está fuera del alcance contratado del cliente.",
              client=str(client.id), hostname=v.hostname)
    if settings.require_target_verification and not target.verified_at:
        _deny(db, user, request, 403, "target_unverified",
              "El dominio aún no está verificado (registro TXT DNS).", target=str(target.id))
    if body.mode == "active_safe" and not target.active_scan_allowed:
        _deny(db, user, request, 403, "active_not_allowed",
              "El contrato de este objetivo solo autoriza escaneo pasivo.", target=str(target.id))
    # 3) consentimiento explícito
    if (not body.consent.accepted or body.consent.statement_version != CONSENT_VERSION):
        _deny(db, user, request, 400, "consent_missing",
              "Debes aceptar la declaración de autorización vigente antes de escanear.")
    # 4) cuotas y exclusión mutua
    active = db.scalar(select(func.count()).select_from(Scan).where(
        Scan.org_id == user.org_id, Scan.status.in_(("queued", "running"))))
    if active >= settings.max_active_scans_per_org:
        raise HTTPException(429, "Límite de escaneos simultáneos alcanzado")
    if db.scalar(select(Scan.id).where(Scan.target_id == target.id, Scan.status.in_(("queued", "running")))):
        raise HTTPException(409, "Ya hay un escaneo en curso para este objetivo")

    text = consent_statement(v.hostname, body.mode)
    consent = ConsentRecord(org_id=user.org_id, user_id=user.id, client_id=client.id, target_id=target.id,
                            hostname=v.hostname, mode=body.mode, statement_version=CONSENT_VERSION,
                            statement_sha256=statement_sha256(text),
                            authorization_reference=body.consent.authorization_reference.strip(),
                            ip=request.client.host if request.client else None,
                            user_agent=(request.headers.get("user-agent") or "")[:300])
    db.add(consent)
    db.flush()
    scan = Scan(org_id=user.org_id, client_id=client.id, target_id=target.id, requested_by=user.id,
                consent_id=consent.id, target_url=v.url, mode=body.mode, resolved_ips=list(v.resolved_ips))
    db.add(scan)
    db.flush()
    log_event(db, action="scan.created", org_id=user.org_id, actor_id=user.id, resource_type="scan",
              resource_id=scan.id, request=request,
              details={"url": v.url, "mode": body.mode, "consent_id": str(consent.id),
                       "authorization_reference": consent.authorization_reference})
    db.commit()                                   # confirmar ANTES de encolar: el worker debe ver la fila
    try:
        scan.celery_task_id = run_scan.delay(str(scan.id), str(user.org_id)).id
    except Exception:
        db.execute(update(Scan).where(Scan.id == scan.id).values(status="failed", error="No se pudo encolar"))
        db.commit()
        raise HTTPException(503, "Cola de trabajos no disponible")
    db.commit()
    return _scan_out(scan)


@router.get("/scans")
def list_scans(client_id: uuid.UUID | None = None, limit: int = Query(50, le=200),
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    visible = visible_clients_query(user).with_only_columns(Client.id)
    q = select(Scan).where(Scan.org_id == user.org_id, Scan.client_id.in_(visible))
    if client_id:
        q = q.where(Scan.client_id == client_id)
    return [_scan_out(s) for s in db.scalars(q.order_by(Scan.queued_at.desc()).limit(limit))]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _scan_out(_get_scan(db, user, scan_id))


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: uuid.UUID, request: Request, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    scan = _get_scan(db, user, scan_id)
    if user.role != "admin" and scan.requested_by != user.id:
        raise HTTPException(403, "Solo quien lanzó el escaneo (o un Admin) puede cancelarlo")
    if scan.status == "queued":
        db.execute(update(Scan).where(Scan.id == scan.id, Scan.status == "queued")
                   .values(status="cancelled", finished_at=utcnow()))
    elif scan.status == "running":
        redis_client().set(cancel_key(scan.id), "1", ex=86400)   # "kill switch": el worker lo consulta cada ~5 s
    else:
        raise HTTPException(409, "El escaneo ya terminó")
    log_event(db, action="scan.cancel_requested", org_id=user.org_id, actor_id=user.id,
              resource_type="scan", resource_id=scan.id, request=request)
    db.commit()
    return {"detail": "Cancelación solicitada"}


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: uuid.UUID, request: Request, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    scan = _get_scan(db, user, scan_id)
    rows = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    log_event(db, action="findings.read", org_id=user.org_id, actor_id=user.id, resource_type="scan",
              resource_id=scan.id, request=request, details={"count": len(rows)})
    db.commit()
    return [{"id": f.id, "severity": f.severity, "title": f.title, "url": f.url, "method": f.method,
             "param": f.param, "cwe_id": f.cwe_id, "confidence": f.confidence,
             "description": f.description, "solution": f.solution, "evidence": f.evidence} for f in rows]


@router.get("/scans/{scan_id}/reports")
def scan_reports(scan_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = _get_scan(db, user, scan_id)
    return [{"id": r.id, "format": r.format, "size_bytes": r.size_bytes, "sha256": r.sha256,
             "created_at": r.created_at} for r in db.scalars(select(Report).where(Report.scan_id == scan.id))]


_MEDIA = {"html": "text/html; charset=utf-8", "pdf": "application/pdf"}


@router.get("/reports/{report_id}/download")
def download_report(report_id: uuid.UUID, request: Request, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    rep = db.get(Report, report_id)
    if not rep:
        raise HTTPException(404, "Reporte no encontrado")
    _get_scan(db, user, rep.scan_id)                              # misma regla de visibilidad que el escaneo
    data = report_service.read_report(rep)
    log_event(db, action="report.downloaded", org_id=user.org_id, actor_id=user.id, resource_type="report",
              resource_id=rep.id, request=request, details={"format": rep.format})
    db.commit()
    return Response(data, media_type=_MEDIA[rep.format], headers={
        "Content-Disposition": f'attachment; filename="report-{rep.scan_id}.{rep.format}"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        # El HTML contiene datos del objetivo: aunque se abra en el navegador no ejecuta scripts ni carga nada.
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'"})
