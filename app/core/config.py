from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = "development"
    base_url: str = "http://localhost:8000"
    cors_origins: list[str] = []
    trusted_hosts: list[str] = ["localhost", "127.0.0.1"]
    allow_open_registration: bool = True

    database_url: str
    redis_url: str = "redis://redis:6379/0"

    jwt_secret: SecretStr
    data_encryption_key: SecretStr

    access_token_minutes: int = 15
    refresh_token_days: int = 7
    challenge_token_minutes: int = 5
    verify_token_hours: int = 24
    invite_token_days: int = 7

    smtp_host: str = "mailhog"
    smtp_port: int = 1025
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = False
    smtp_from: str = "no-reply@vulnaudit.local"
    resend_api_key: str | None = None

    zap_url: str = "http://zap:8080"
    zap_api_key: SecretStr
    scan_max_minutes: int = 120
    scan_threads_per_host: int = 2
    scan_delay_ms: int = 200
    scanner_user_agent: str = "VulnAudit-Scanner/1.0"
    zap_extra_enabled_rules: list[int] = [40012]
    zap_disabled_rules: list[int] = []

    allowed_ports: list[int] = [80, 443, 8080, 8443]
    require_target_verification: bool = True
    max_active_scans_per_org: int = 3
    reports_dir: str = "/data/reports"

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_strong(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("jwt_secret debe tener al menos 32 caracteres")
        return v

    @field_validator("data_encryption_key")
    @classmethod
    def _fernet_valid(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) != 44:
            raise ValueError("data_encryption_key debe ser una Fernet key válida (44 chars)")
        return v

    @field_validator("zap_api_key")
    @classmethod
    def _zap_key_strong(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 16:
            raise ValueError("zap_api_key debe tener al menos 16 caracteres")
        return v

settings = Settings()
