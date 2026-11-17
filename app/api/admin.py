import secrets
import uuid
from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_or_404, get_current_user, get_db, require_role, visible_clients_query
from app.core.audit import log_event
from app.core.config import settings
from app.core.security import new_opaque_token, utcnow
from app.core.ssrf import UnsafeTargetError, validate_public_url
from app.db.models import AuditLog, Client, ClientAssignment, Invitation, Target, User
from app.services.targets import check_dns_txt, normalize_hostname
from app.worker.tasks import send_email

router = APIRouter(tags=["admin"])
admin_only = require_role("admin")


class ClientIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    legal_name: str | None = Field(default=None, max_length=200)
    contact_email: EmailStr | None = None
    contract_ref: str = Field(min_length=2, max_length=200)
    contract_start: date
    contract_end: date

    @model_validator(mode="after")
    def _dates(self):
        if self.contract_end < self.contract_start:
            raise ValueError("contract_end debe ser >= contract_start")
        return self


class TargetIn(BaseModel):
    hostname: str = Field(max_length=253)
    include_subdomains: bool = False
    active_scan_allowed: bool = False


class InviteIn(BaseModel):
    email: EmailStr
    role: Literal["admin", "auditor"] = "auditor"


def _client_out(c: Client) -> dict:
    return {"id": c.id, "name": c.name, "contract_ref": c.contract_ref, "contract_start": c.contract_start,
            "contract_end": c.contract_end, "status": c.status}


def _target_out(t: Target) -> dict:
    return {"id": t.id, "hostname": t.hostname, "include_subdomains": t.include_subdomains,
            "active_scan_allowed": t.active_scan_allowed, "verified": t.verified_at is not None}


# ── Clientes ──
@router.post("/clients", status_code=201)
def create_client(body: ClientIn, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    if db.scalar(select(Client.id).where(Client.org_id == user.org_id, Client.name == body.name)):
        raise HTTPException(409, "Ya existe un cliente con ese nombre")
    c = Client(org_id=user.org_id, created_by=user.id, **body.model_dump(mode="python"))
    db.add(c)
    db.flush()
    log_event(db, action="client.created", org_id=user.org_id, actor_id=user.id, resource_type="client",
              resource_id=c.id, request=request, details={"contract_ref": c.contract_ref})
    db.commit()
    return _client_out(c)


@router.get("/clients")
def list_clients(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [_client_out(c) for c in db.scalars(visible_clients_query(user).order_by(Client.name))]


@router.post("/clients/{client_id}/assignments", status_code=201)
def assign_auditor(client_id: uuid.UUID, body: dict, request: Request, user: User = Depends(admin_only),
                   db: Session = Depends(get_db)):
    c = get_client_or_404(db, user, client_id)
    try:
        auditor_id = uuid.UUID(str(body.get("user_id")))
    except ValueError:
        raise HTTPException(422, "user_id inválido")
    auditor = db.scalar(select(User).where(User.id == auditor_id, User.org_id == user.org_id,
                                           User.role == "auditor", User.is_active.is_(True)))
    if not auditor:
        raise HTTPException(404, "Auditor no encontrado")
    if not db.get(ClientAssignment, (c.id, auditor.id)):
        db.add(ClientAssignment(client_id=c.id, user_id=auditor.id, org_id=user.org_id, assigned_by=user.id))
    log_event(db, action="client.auditor_assigned", org_id=user.org_id, actor_id=user.id,
              resource_type="client", resource_id=c.id, request=request, details={"auditor": str(auditor.id)})
    db.commit()
    return {"client_id": c.id, "user_id": auditor.id}


@router.delete("/clients/{client_id}/assignments/{auditor_id}", status_code=204)
def unassign_auditor(client_id: uuid.UUID, auditor_id: uuid.UUID, request: Request,
                     user: User = Depends(admin_only), db: Session = Depends(get_db)):
    c = get_client_or_404(db, user, client_id)
    a = db.get(ClientAssignment, (c.id, auditor_id))
    if a:
        db.delete(a)
    log_event(db, action="client.auditor_unassigned", org_id=user.org_id, actor_id=user.id,
              resource_type="client", resource_id=c.id, request=request, details={"auditor": str(auditor_id)})
    db.commit()


# ── Alcance (targets) ──
@router.post("/clients/{client_id}/targets", status_code=201)
def create_target(client_id: uuid.UUID, body: TargetIn, request: Request, user: User = Depends(admin_only),
                  db: Session = Depends(get_db)):
    c = get_client_or_404(db, user, client_id)
    host = normalize_hostname(body.hostname)
    if not host:
        raise HTTPException(422, "Hostname inválido (solo nombres de dominio, sin esquema ni IPs)")
    try:                                              # SSRF: debe ser público y resolver a IPs públicas
        validate_public_url(f"https://{host}/", allowed_ports=settings.allowed_ports)
    except UnsafeTargetError as e:
        log_event(db, action="target.rejected", org_id=user.org_id, actor_id=user.id, request=request,
                  details={"hostname": host, "reason": e.code})
        db.commit()
        raise HTTPException(422, str(e))
    if db.scalar(select(Target.id).where(Target.client_id == c.id, Target.hostname == host)):
        raise HTTPException(409, "El objetivo ya existe para este cliente")
    token = secrets.token_hex(16)
    t = Target(org_id=user.org_id, client_id=c.id, hostname=host, include_subdomains=body.include_subdomains,
               active_scan_allowed=body.active_scan_allowed, verification_token=token, created_by=user.id)
    db.add(t)
    db.flush()
    log_event(db, action="target.created", org_id=user.org_id, actor_id=user.id, resource_type="target",
              resource_id=t.id, request=request, details={"hostname": host, "active": t.active_scan_allowed})
    db.commit()
    return {**_target_out(t), "verification": {"type": "TXT", "name": f"_vulnaudit-verify.{host}",
                                               "value": f"vulnaudit-verify={token}"}}


@router.get("/clients/{client_id}/targets")
def list_targets(client_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    c = get_client_or_404(db, user, client_id)
    return [_target_out(t) for t in db.scalars(select(Target).where(Target.client_id == c.id))]


@router.post("/targets/{target_id}/verify")
def verify_target(target_id: uuid.UUID, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t or t.org_id != user.org_id:
        raise HTTPException(404, "Objetivo no encontrado")
    ok = check_dns_txt(t.hostname, t.verification_token)
    if ok and not t.verified_at:
        t.verified_at = utcnow()
    log_event(db, action="target.verified" if ok else "target.verify_failed", org_id=user.org_id,
              actor_id=user.id, resource_type="target", resource_id=t.id, request=request)
    db.commit()
    if not ok:
        raise HTTPException(422, "No se encontró el registro TXT esperado (la propagación DNS puede tardar)")
    return _target_out(t)


# ── Usuarios ──
@router.post("/users/invitations", status_code=201)
def invite_user(body: InviteIn, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "Ese email ya tiene cuenta")
    raw, h = new_opaque_token()
    inv = Invitation(org_id=user.org_id, email=email, role=body.role, token_hash=h, invited_by=user.id,
                     expires_at=utcnow() + timedelta(days=settings.invite_token_days))
    db.add(inv)
    db.flush()
    log_event(db, action="user.invited", org_id=user.org_id, actor_id=user.id, resource_type="invitation",
              resource_id=inv.id, request=request, details={"email": email, "role": body.role})
    db.commit()
    send_email.delay(email, "Invitación a VulnAudit",
                     f"Has sido invitado como {body.role}. Regístrate con este token de invitación:\n\n{raw}")
    return {"detail": "Invitación enviada", "invitation_id": inv.id}


@router.get("/users")
def list_users(user: User = Depends(admin_only), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).where(User.org_id == user.org_id).order_by(User.email))
    return [{"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active,
             "email_verified": u.email_verified_at is not None, "totp_enabled": u.totp_enabled_at is not None}
            for u in rows]


# ── Trazabilidad ──
@router.get("/audit-logs")
def audit_logs(limit: int = 100, before_seq: int | None = None, user: User = Depends(admin_only),
               db: Session = Depends(get_db)):
    q = select(AuditLog).where(AuditLog.org_id == user.org_id)
    if before_seq:
        q = q.where(AuditLog.seq < before_seq)
    rows = db.scalars(q.order_by(AuditLog.seq.desc()).limit(min(max(limit, 1), 500)))
    return [{"seq": r.seq, "at": r.created_at, "actor": r.actor_user_id, "action": r.action,
             "resource": f"{r.resource_type}:{r.resource_id}" if r.resource_type else None,
             "ip": r.ip, "details": r.details, "hash": r.entry_hash} for r in rows]
