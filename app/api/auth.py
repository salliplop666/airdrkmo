import logging
import smtplib
import uuid
from datetime import timedelta
from email.mime.text import MIMEText

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import challenge_user, get_db, ip_of
from app.core.audit import log_event
from app.core.config import settings
from app.core.ratelimit import rate_limit
from app.core.security import (
    DUMMY_HASH, create_jwt, hash_password, new_opaque_token,
    new_totp_secret, sha256_hex, totp_uri, utcnow, verify_password, verify_totp,
)
from app.db.models import EmailVerification, Invitation, Organization, RefreshToken, User

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger(__name__)

GENERIC_REGISTER = {"detail": "Si el registro es válido, recibirás un correo para continuar."}
MAX_FAILED, LOCK_MINUTES = 10, 15


def _safe_rate_limit(bucket: str, key: str, max_hits: int, window: int) -> None:
    """Rate limit con fallback: si Redis no está disponible, no bloquea el registro."""
    try:
        rate_limit(bucket, key, max_hits, window)
    except Exception as exc:
        log.warning("rate_limit indisponible (%s/%s): %s", bucket, key, exc)


def _email_async(to: str, subject: str, body: str) -> None:
    """Envío por Resend API REST. Funciona en Render (sin problemas de IP como Gmail)."""
    import httpx
    api_key = getattr(settings, "resend_api_key", None)
    if not api_key:
        log.warning("RESEND_API_KEY no configurada. Token de verificación NO enviado.")
        return
    try:
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": "VulnAudit <onboarding@resend.dev>",  # dominio de prueba gratuito
                "to": [to],
                "subject": subject,
                "text": body,
            },
            timeout=15,
        )
        resp.raise_for_status()
        log.info("Correo enviado a %s via Resend (id=%s)", to, resp.json().get("id"))
    except Exception:
        log.exception("Fallo Resend al enviar a %s", to)


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    org_name: str | None = Field(default=None, min_length=2, max_length=120)
    invite_token: str | None = Field(default=None, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)


class TokenIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)


@router.post("/register", status_code=202)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    _safe_rate_limit("register", ip_of(request), 10, 3600)
    email, now = body.email.lower(), utcnow()

    try:
        if db.scalar(select(User.id).where(User.email == email)):
            return GENERIC_REGISTER

        invitation = None
        if body.invite_token:
            invitation = db.scalar(
                select(Invitation).where(Invitation.token_hash == sha256_hex(body.invite_token))
            )
            if (not invitation or invitation.accepted_at or invitation.expires_at < now
                    or invitation.email != email):
                raise HTTPException(400, "Invitación inválida o expirada")
            org_id, role = invitation.org_id, invitation.role
        else:
            if not settings.allow_open_registration:
                raise HTTPException(403, "El registro abierto está deshabilitado")
            if not body.org_name:
                raise HTTPException(422, "org_name es obligatorio")
            org = Organization(name=body.org_name)
            db.add(org)
            db.flush()
            org_id, role = org.id, "admin"

        user = User(
            org_id=org_id, email=email,
            password_hash=hash_password(body.password), role=role,
            email_verified_at=now if invitation else None,
        )
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return GENERIC_REGISTER

        raw = None
        if invitation:
            invitation.accepted_at = now
        else:
            raw, h = new_opaque_token()
            db.add(EmailVerification(
                user_id=user.id, token_hash=h,
                expires_at=now + timedelta(hours=settings.verify_token_hours)
            ))

        log_event(
            db, action="user.registered", org_id=org_id, actor_id=user.id,
            resource_type="user", resource_id=user.id, request=request,
            details={"role": role, "via_invitation": bool(invitation)}
        )
        db.commit()

        if raw:
            _email_async(
                email, "Verifica tu cuenta de VulnAudit",
                f"Verifica tu email con este token (válido {settings.verify_token_hours} h):\n\n{raw}\n\n"
                f"{settings.base_url}/verify-email?token={raw}",
            )
        return GENERIC_REGISTER

    except SQLAlchemyError as exc:
        db.rollback()
        log.error("Fallo de base de datos en /register: %s", exc)
        raise HTTPException(
            503,
            "La base de datos no está disponible. Verifica DATABASE_URL y que el schema.sql esté aplicado.",
        )


@router.post("/verify-email")
def verify_email(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    _safe_rate_limit("verify", ip_of(request), 20, 3600)
    ev = db.scalar(
        select(EmailVerification).where(EmailVerification.token_hash == sha256_hex(body.token))
    )
    now = utcnow()
    if not ev or ev.used_at or ev.expires_at < now:
        raise HTTPException(400, "Token inválido o expirado")
    user = db.get(User, ev.user_id)
    user.email_verified_at, ev.used_at = now, now
    log_event(db, action="user.email_verified", org_id=user.org_id, actor_id=user.id, request=request)
    db.commit()
    return {"detail": "Email verificado. Ya puedes iniciar sesión."}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    email, ip = body.email.lower(), ip_of(request)
    _safe_rate_limit("login-ip", ip, 30, 900)
    _safe_rate_limit("login-email", email, 10, 900)

    user = db.scalar(select(User).where(User.email == email))
    bad = HTTPException(401, "Credenciales incorrectas")
    if user is None:
        verify_password(body.password, DUMMY_HASH)
        log_event(db, action="auth.login_failed", request=request, details={"reason": "unknown_user"})
        db.commit()
        raise bad

    if user.locked_until and user.locked_until > utcnow():
        raise HTTPException(423, "Cuenta bloqueada temporalmente por intentos fallidos")

    if not verify_password(body.password, user.password_hash) or not user.is_active:
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED:
            user.locked_until, user.failed_login_count = utcnow() + timedelta(minutes=LOCK_MINUTES), 0
        log_event(db, action="auth.login_failed", org_id=user.org_id, actor_id=user.id,
                  request=request, details={"reason": "bad_password"})
        db.commit()
        raise bad

    if not user.email_verified_at:
        raise HTTPException(403, "Debes verificar tu email antes de iniciar sesión")

    user.failed_login_count = 0
    scope = "mfa" if user.totp_enabled_at else "enroll"
    log_event(db, action="auth.password_ok", org_id=user.org_id, actor_id=user.id,
              request=request, details={"next": scope})
    db.commit()

    return {
        "next": "totp" if scope == "mfa" else "totp_enrollment",
        "challenge_token": create_jwt(user.id, scope, settings.challenge_token_minutes),
    }


def _issue_tokens(db: Session, user: User, family_id: uuid.UUID | None = None) -> dict:
    raw, h = new_opaque_token()
    db.add(RefreshToken(
        user_id=user.id, family_id=family_id or uuid.uuid4(), token_hash=h,
        expires_at=utcnow() + timedelta(days=settings.refresh_token_days)
    ))
    user.last_login_at = utcnow()
    return {
        "access_token": create_jwt(
            user.id, "access", settings.access_token_minutes,
            org=str(user.org_id), role=user.role
        ),
        "refresh_token": raw,
        "token_type": "bearer",
        "expires_in": settings.access_token_minutes * 60,
    }


@router.post("/2fa/setup")
def totp_setup(user: User = Depends(challenge_user("enroll")), db: Session = Depends(get_db)):
    if user.totp_enabled_at:
        raise HTTPException(409, "2FA ya está activado")
    secret = new_totp_secret()
    user.totp_secret_enc = secret
    db.commit()
    return {"secret": secret, "otpauth_uri": totp_uri(secret, user.email)}


@router.post("/2fa/confirm")
def totp_confirm(body: CodeIn, request: Request,
                 user: User = Depends(challenge_user("enroll")),
                 db: Session = Depends(get_db)):
    _safe_rate_limit("totp", str(user.id), 10, 900)
    if not user.totp_secret_enc or user.totp_enabled_at:
        raise HTTPException(409, "Inicia la configuración de 2FA primero")
    step = verify_totp(user.totp_secret_enc, body.code, user.totp_last_step)
    if step is None:
        log_event(db, action="auth.totp_failed", org_id=user.org_id, actor_id=user.id,
                  request=request, details={"phase": "enroll"})
        db.commit()
        raise HTTPException(401, "Código incorrecto")
    user.totp_enabled_at, user.totp_last_step = utcnow(), step
    tokens = _issue_tokens(db, user)
    log_event(db, action="auth.2fa_enabled", org_id=user.org_id, actor_id=user.id, request=request)
    db.commit()
    return tokens


@router.post("/2fa/verify")
def totp_verify(body: CodeIn, request: Request,
                user: User = Depends(challenge_user("mfa")),
                db: Session = Depends(get_db)):
    _safe_rate_limit("totp", str(user.id), 10, 900)
    step = (
        verify_totp(user.totp_secret_enc or "", body.code, user.totp_last_step)
        if user.totp_secret_enc else None
    )
    if step is None:
        log_event(db, action="auth.totp_failed", org_id=user.org_id, actor_id=user.id,
                  request=request, details={"phase": "login"})
        db.commit()
        raise HTTPException(401, "Código incorrecto")
    user.totp_last_step = step
    tokens = _issue_tokens(db, user)
    log_event(db, action="auth.login_success", org_id=user.org_id, actor_id=user.id, request=request)
    db.commit()
    return tokens


@router.post("/refresh")
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    _safe_rate_limit("refresh", ip_of(request), 60, 900)
    rt = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(body.refresh_token))
    )
    if rt is None:
        raise HTTPException(401, "Refresh token inválido")
    now = utcnow()
    if rt.revoked_at:
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        db.commit()
        log.warning("Reutilización de refresh token detectada (family=%s)", rt.family_id)
        raise HTTPException(401, "Refresh token inválido")
    user = db.get(User, rt.user_id)
    if rt.expires_at < now or not user or not user.is_active or not user.totp_enabled_at:
        raise HTTPException(401, "Refresh token inválido")
    rt.revoked_at = now
    tokens = _issue_tokens(db, user, rt.family_id)
    db.commit()
    return tokens


@router.post("/logout", status_code=204)
def logout(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    rt = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(body.refresh_token))
    )
    if rt:
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        db.commit()
