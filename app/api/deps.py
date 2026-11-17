import uuid

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decode_jwt
from app.db.models import Client, ClientAssignment, Organization, User
from app.db.session import SessionLocal, set_tenant

bearer = HTTPBearer(auto_error=False)


def get_db():
    with SessionLocal() as db:
        yield db


def _unauthorized() -> HTTPException:
    return HTTPException(401, "Credenciales inválidas o expiradas", headers={"WWW-Authenticate": "Bearer"})


def _load_user(creds: HTTPAuthorizationCredentials | None, scope: str, db: Session) -> User:
    if creds is None:
        raise _unauthorized()
    try:
        payload = decode_jwt(creds.credentials, scope)
        user = db.get(User, uuid.UUID(payload["sub"]))
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized()
    if user is None or not user.is_active:
        raise _unauthorized()
    org = db.get(Organization, user.org_id)
    if org is None or not org.is_active:
        raise _unauthorized()
    return user


def get_current_user(creds=Depends(bearer), db: Session = Depends(get_db)) -> User:
    """Solo acepta access tokens (emitidos tras password + TOTP) de usuarios verificados con 2FA activo."""
    user = _load_user(creds, "access", db)
    if not user.email_verified_at or not user.totp_enabled_at:
        raise _unauthorized()
    set_tenant(db, user.org_id)
    return user


def challenge_user(scope: str):
    """Token intermedio del login: 'mfa' (pedir TOTP) o 'enroll' (configurar TOTP)."""
    def dep(creds=Depends(bearer), db: Session = Depends(get_db)) -> User:
        user = _load_user(creds, scope, db)
        set_tenant(db, user.org_id)
        return user
    return dep


def require_role(*roles: str):
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Permisos insuficientes")
        return user
    return dep


def visible_clients_query(user: User):
    """Admin: todos los clientes de su organización. Auditor: solo los asignados."""
    q = select(Client).where(Client.org_id == user.org_id)
    if user.role != "admin":
        q = q.join(ClientAssignment, ClientAssignment.client_id == Client.id).where(
            ClientAssignment.user_id == user.id)
    return q


def get_client_or_404(db: Session, user: User, client_id: uuid.UUID) -> Client:
    client = db.scalar(visible_clients_query(user).where(Client.id == client_id))
    if client is None:
        raise HTTPException(404, "Cliente no encontrado")     # 404 (no 403): no revela que existe
    return client


def ip_of(request: Request) -> str:
    return request.client.host if request.client else "unknown"
