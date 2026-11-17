import re

from app.db.models import Target

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+(?!\d+$)[a-z0-9-]{2,63}$")


def normalize_hostname(raw: str) -> str | None:
    host = raw.strip().lower().rstrip(".")
    return host if _DOMAIN_RE.match(host) else None


def hostname_in_scope(host: str, target: Target) -> bool:
    return host == target.hostname or (target.include_subdomains and host.endswith("." + target.hostname))


def check_dns_txt(hostname: str, token: str) -> bool:
    """Prueba de control del dominio: TXT en _vulnaudit-verify.<host> con 'vulnaudit-verify=<token>'."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(f"_vulnaudit-verify.{hostname}", "TXT", lifetime=5)
    except Exception:
        return False
    expected = f"vulnaudit-verify={token}"
    return any(b"".join(r.strings).decode(errors="ignore").strip() == expected for r in answers)
