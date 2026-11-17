"""Trazabilidad: quién hizo qué, cuándo y desde dónde.
Registro append-only (trigger en Postgres) con cadena de hashes por organización
(cada entrada incluye el hash de la anterior → cualquier alteración posterior es detectable)."""
import hashlib
import json
import uuid

from fastapi import Request
from sqlalchemy import insert, select, text
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.db.models import AuditLog
from app.db.session import set_tenant


def log_event(db: Session, *, action: str, org_id=None, actor_id=None, resource_type: str | None = None,
              resource_id=None, request: Request | None = None, details: dict | None = None) -> None:
    ip = ua = None
    if request is not None:
        ip = request.client.host if request.client else None
        ua = (request.headers.get("user-agent") or "")[:300]
    prev = None
    if org_id:
        set_tenant(db, org_id)
        # Serializa las escrituras de auditoría de la misma organización para que la cadena sea lineal.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"audit:{org_id}"})
        prev = db.scalar(select(AuditLog.entry_hash).where(AuditLog.org_id == org_id)
                         .order_by(AuditLog.seq.desc()).limit(1))
    entry_id, now = uuid.uuid4(), utcnow()
    canonical = json.dumps({"id": str(entry_id), "org": str(org_id), "actor": str(actor_id),
                            "action": action, "rt": resource_type, "rid": str(resource_id),
                            "ip": ip, "details": details or {}, "at": now.isoformat()},
                           sort_keys=True, default=str)
    entry_hash = hashlib.sha256(((prev or "") + canonical).encode()).hexdigest()
    # Core insert (sin RETURNING): la política RLS de INSERT es permisiva, la de SELECT no.
    db.execute(insert(AuditLog.__table__).values(
        id=entry_id, org_id=org_id, actor_user_id=actor_id, action=action,
        resource_type=resource_type, resource_id=None if resource_id is None else str(resource_id),
        ip=ip, user_agent=ua, details=details or {}, prev_hash=prev, entry_hash=entry_hash, created_at=now))
