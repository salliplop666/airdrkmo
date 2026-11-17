"""Generación de reportes HTML/PDF. Los hallazgos contienen texto controlado por el objetivo
(cabeceras, cuerpos, parámetros): por eso Jinja2 va con autoescape TOTAL y WeasyPrint con
un url_fetcher que bloquea cualquier recurso externo (evita SSRF/XSS vía el propio reporte)."""
import hashlib
import uuid
from pathlib import Path

from jinja2 import Environment, PackageLoader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decrypt_bytes, encrypt_bytes, utcnow
from app.db.models import Client, ConsentRecord, Finding, Report, Scan, Target, User

_env = Environment(loader=PackageLoader("app", "templates"), autoescape=True)
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EVIDENCE_MAX = 4000


def _deny_fetch(url, *args, **kwargs):
    raise ValueError("Recursos externos deshabilitados en reportes")


def html_to_pdf(html: str) -> bytes:
    from weasyprint import HTML          # import perezoso: necesita librerías nativas (pango)
    return HTML(string=html, url_fetcher=_deny_fetch).write_pdf()


def render_html(db: Session, scan: Scan) -> str:
    client, target = db.get(Client, scan.client_id), db.get(Target, scan.target_id)
    auditor, consent = db.get(User, scan.requested_by), db.get(ConsentRecord, scan.consent_id)
    findings = sorted(db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all(),
                      key=lambda f: (SEV_ORDER.get(f.severity, 9), f.title))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    return _env.get_template("report.html.j2").render(
        scan=scan, client=client, target=target, auditor=auditor, consent=consent,
        findings=findings, counts=counts, evidence_max=EVIDENCE_MAX, generated_at=utcnow())


def _store(db: Session, scan: Scan, fmt: str, data: bytes, created_by: uuid.UUID) -> Report:
    report_id = uuid.uuid4()
    key = f"{scan.org_id}/{scan.client_id}/{scan.id}/{report_id}.{fmt}.enc"     # solo UUIDs: sin path traversal
    path = Path(settings.reports_dir) / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encrypt_bytes(data))
    rep = Report(id=report_id, org_id=scan.org_id, client_id=scan.client_id, scan_id=scan.id, format=fmt,
                 storage_key=key, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                 created_by=created_by)
    db.add(rep)
    return rep


def build_reports(db: Session, scan: Scan) -> list[Report]:
    html = render_html(db, scan)
    out = [_store(db, scan, "html", html.encode(), scan.requested_by)]
    try:
        out.append(_store(db, scan, "pdf", html_to_pdf(html), scan.requested_by))
    except Exception:                    # sin libs de PDF el HTML sigue disponible
        import logging
        logging.getLogger(__name__).exception("PDF generation failed")
    return out


def read_report(report: Report) -> bytes:
    data = decrypt_bytes((Path(settings.reports_dir) / report.storage_key).read_bytes())
    if hashlib.sha256(data).hexdigest() != report.sha256:
        raise RuntimeError("Integridad del reporte comprometida")
    return data
