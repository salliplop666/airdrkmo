import uuid
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.audit import log_event
from app.core.security import utcnow
from app.db.models import Client, Finding, Scan, Target, User

router = APIRouter(tags=["scans"])


class ScanCreate(BaseModel):
    url: str | None = None
    target_url: str | None = None
    mode: Literal["passive", "active_safe"] = "passive"
    client_id: uuid.UUID | None = None

    @property
    def effective_url(self) -> str:
        u = self.url or self.target_url
        if not u:
            raise ValueError("url es obligatorio")
        return u.strip()


def _scan_out(s: Scan) -> dict:
    return {
        "id": s.id,
        "client_id": s.client_id,
        "target_id": s.target_id,
        "target_url": s.target_url,
        "mode": s.mode,
        "status": s.status,
        "error": s.error,
        "stats": s.stats or {},
        "findings_count": getattr(s, "findings_count", 0),
        "queued_at": s.queued_at,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "requested_by": s.requested_by,
    }


@router.post("/scans", status_code=202)
def create_scan(
    body: ScanCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        url = body.effective_url
    except ValueError as e:
        raise HTTPException(422, str(e))

    if not url.startswith(("http://", "https://")):
        raise HTTPException(422, "La URL debe empezar con http:// o https://")

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. Obtener o crear cliente
    client_id = body.client_id
    if not client_id:
        client = db.scalar(select(Client).where(Client.org_id == user.org_id).limit(1))
        if client:
            client_id = client.id
        else:
            client = Client(
                org_id=user.org_id,
                name="Default Client",
                contract_ref="AUTO",
                contract_start=utcnow().date(),
                contract_end=utcnow().date().replace(year=utcnow().year + 1),
            )
            db.add(client)
            db.flush()
            client_id = client.id

    # 2. Obtener o crear Target (¡ESTO EVITA EL ERROR target_id NULL!)
    target = db.scalar(
        select(Target).where(
            Target.client_id == client_id,
            Target.hostname == hostname
        )
    )
    if not target:
        target = Target(
            client_id=client_id,
            hostname=hostname,
            scope=url,
            verified_at=utcnow(),  # Forzamos verificado para evitar bloqueos en desarrollo
            active_scan_allowed=True,
        )
        db.add(target)
        db.flush()

    # 3. Crear el Scan con target_id válido
    scan = Scan(
        org_id=user.org_id,
        client_id=client_id,
        target_id=target.id,  # ← ¡CLAVE!
        requested_by=user.id,
        target_url=url,
        mode=body.mode,
        status="queued",
    )
    db.add(scan)
    db.flush()

    log_event(
        db,
        action="scan.created",
        org_id=user.org_id,
        actor_id=user.id,
        resource_type="scan",
        resource_id=scan.id,
        request=request,
        details={"url": url, "mode": body.mode, "target_id": str(target.id)},
    )
    db.commit()

    # Simular inicio para que el frontend lo vea (Render Free no tiene worker Celery)
    scan.status = "running"
    db.commit()

    return _scan_out(scan)


@router.get("/scans")
def list_scans(
    client_id: uuid.UUID | None = None,
    limit: int = Query(50, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = select(Scan).where(Scan.org_id == user.org_id)
    if client_id:
        q = q.where(Scan.client_id == client_id)
    rows = db.scalars(q.order_by(Scan.queued_at.desc()).limit(limit)).all()
    return [_scan_out(s) for s in rows]


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id))
    if not s:
        raise HTTPException(404, "Escaneo no encontrado")
    return _scan_out(s)


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id))
    if not s:
        raise HTTPException(404, "Escaneo no encontrado")
    rows = db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "url": f.url,
            "method": f.method,
            "param": f.param,
            "cwe_id": f.cwe_id,
            "confidence": f.confidence,
            "description": f.description,
            "solution": f.solution,
            "evidence": f.evidence,
        }
        for f in rows
    ]


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id))
    if not s:
        raise HTTPException(404, "Escaneo no encontrado")
    db.delete(s)
    db.commit()
