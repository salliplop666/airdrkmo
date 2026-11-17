import uuid
from datetime import date, datetime
from typing import Annotated

from sqlalchemy import (BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, Text, Uuid,
                        func, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.core.security import decrypt_text, encrypt_text


class Base(DeclarativeBase):
    pass


class EncryptedText(TypeDecorator):
    """Cifra/descifra de forma transparente (Fernet). Usado para evidencias y secretos."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt_text(value)

    def process_result_value(self, value, dialect):
        return None if value is None else decrypt_text(value)


PK = Annotated[uuid.UUID, mapped_column(Uuid, primary_key=True, default=uuid.uuid4)]
Created = Annotated[datetime, mapped_column(DateTime(timezone=True), server_default=func.now())]
OrgFK = Annotated[uuid.UUID, mapped_column(Uuid, ForeignKey("organizations.id"), index=True)]
TS = DateTime(timezone=True)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[PK]
    name: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    created_at: Mapped[Created]


class User(Base):
    __tablename__ = "users"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    email: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)                       # admin | auditor
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    email_verified_at: Mapped[datetime | None] = mapped_column(TS)
    totp_secret_enc: Mapped[str | None] = mapped_column(EncryptedText)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(TS)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    locked_until: Mapped[datetime | None] = mapped_column(TS)
    last_login_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[Created]


class Invitation(Base):
    __tablename__ = "invitations"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    email: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    invited_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(TS)
    accepted_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[Created]


class EmailVerification(Base):
    __tablename__ = "email_verifications"
    id: Mapped[PK]
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(TS)
    used_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[Created]


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[PK]
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[Created]


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    name: Mapped[str] = mapped_column(Text)
    legal_name: Mapped[str | None] = mapped_column(Text)
    contact_email: Mapped[str | None] = mapped_column(Text)
    contract_ref: Mapped[str] = mapped_column(Text)
    contract_start: Mapped[date] = mapped_column(Date)
    contract_end: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(Text, default="active", server_default=text("'active'"))
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[Created]


class ClientAssignment(Base):
    __tablename__ = "client_assignments"
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("clients.id"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), primary_key=True)
    org_id: Mapped[OrgFK]
    assigned_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[Created]


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("clients.id"))
    hostname: Mapped[str] = mapped_column(Text)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    active_scan_allowed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    verification_token: Mapped[str] = mapped_column(Text)
    verified_at: Mapped[datetime | None] = mapped_column(TS)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[Created]


class ConsentRecord(Base):
    __tablename__ = "consent_records"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("clients.id"))
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("targets.id"))
    hostname: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text)
    statement_version: Mapped[str] = mapped_column(Text)
    statement_sha256: Mapped[str] = mapped_column(Text)
    authorization_reference: Mapped[str] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    accepted_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("clients.id"))
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("targets.id"))
    requested_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    consent_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("consent_records.id"))
    target_url: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="queued", server_default=text("'queued'"))
    celery_task_id: Mapped[str | None] = mapped_column(Text)
    resolved_ips: Mapped[list | None] = mapped_column(JSONB)
    stats: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    queued_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(TS)
    finished_at: Mapped[datetime | None] = mapped_column(TS)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id"))
    rule_id: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(Text)
    param: Mapped[str | None] = mapped_column(Text)
    cwe_id: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    solution: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column("evidence_enc", EncryptedText)
    fingerprint: Mapped[str] = mapped_column(Text)
    created_at: Mapped[Created]


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[PK]
    org_id: Mapped[OrgFK]
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("clients.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id"))
    format: Mapped[str] = mapped_column(Text)
    storage_key: Mapped[str] = mapped_column(Text, unique=True)
    sha256: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[Created]


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))   # IDENTITY en la BD
    org_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("organizations.id"))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str | None] = mapped_column(Text)
    resource_id: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(Text)
    entry_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS)
