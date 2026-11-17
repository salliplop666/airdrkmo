"""Primitivas: hashing de contraseñas, JWT, tokens opacos, TOTP y cifrado en reposo."""
import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet

from app.core.config import settings

_ph = PasswordHasher()
# Hash "señuelo": se verifica aunque el usuario no exista, para igualar tiempos de respuesta.
DUMMY_HASH = _ph.hash("timing-equalizer")
_fernet = Fernet(settings.data_encryption_key.get_secret_value().encode())
TOTP_PERIOD = 30


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Contraseñas ──
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ── Tokens opacos (verificación de email, invitaciones, refresh): solo se guarda el hash ──
def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_opaque_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)


# ── JWT con "scope": access | mfa (esperando TOTP) | enroll (debe configurar TOTP) ──
def create_jwt(sub: uuid.UUID, scope: str, minutes: int, **claims) -> str:
    now = utcnow()
    payload = {"sub": str(sub), "scope": scope, "iat": now,
               "exp": now + timedelta(minutes=minutes), "jti": uuid.uuid4().hex, **claims}
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm="HS256")


def decode_jwt(token: str, expected_scope: str) -> dict:
    payload = jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=["HS256"],
                         options={"require": ["exp", "sub", "scope"]})
    if payload["scope"] != expected_scope:
        raise jwt.InvalidTokenError("scope incorrecto")
    return payload


# ── TOTP (RFC 6238) con protección anti-replay ──
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="VulnAudit")


def verify_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """Devuelve el time-step aceptado (guárdalo en users.totp_last_step) o None.
    Acepta ±1 ventana de reloj y rechaza cualquier paso <= al último usado (replay)."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // TOTP_PERIOD
    for step in (current - 1, current, current + 1):
        if step > (last_step or 0) and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


# ── Cifrado en reposo (evidencias, secretos TOTP, reportes) ──
def encrypt_text(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode()


def decrypt_text(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode()


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet.encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return _fernet.decrypt(data)
