"""Validación anti-SSRF de URLs objetivo.

Capas: (1) forma de la URL, (2) puerto, (3) resolución DNS y verificación de TODAS las IPs.
Se invoca al registrar el objetivo Y de nuevo justo antes de escanear (el DNS puede cambiar).
Esto NO sustituye el filtrado de egreso a nivel de red (ver README): es defensa en profundidad,
porque quien hace las peticiones es ZAP y él resuelve DNS por su cuenta (rebinding/redirects).
"""
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class UnsafeTargetError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code            # para auditoría; el mensaje al usuario es deliberadamente genérico


_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".lan", ".corp",
                     ".home.arpa", ".localdomain")
_EXTRA_BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
    "64:ff9b::/96", "2001::/32", "2002::/16", "fc00::/7", "fe80::/10", "100::/64"))
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


@dataclass(frozen=True)
class ValidatedUrl:
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


def _assert_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped                                   # ::ffff:127.0.0.1
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global or any(ip in net for net in _EXTRA_BLOCKED)):
        raise UnsafeTargetError("non_public_ip", "El destino no es un host público permitido.")


def validate_public_url(raw: str, *, allowed_ports: list[int], resolver=None) -> ValidatedUrl:
    generic = "URL de destino no permitida."
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or any(c in raw for c in "\\ \t\r\n\x00"):
        raise UnsafeTargetError("malformed", generic)
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTargetError("bad_scheme", "Solo se permiten URLs http/https.")
    if "@" in parts.netloc:
        raise UnsafeTargetError("userinfo", generic)           # evita diferenciales de parseo (ZAP/Java)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise UnsafeTargetError("bad_port", generic)
    if port not in allowed_ports:
        raise UnsafeTargetError("port_not_allowed", f"Puerto no permitido. Permitidos: {sorted(allowed_ports)}")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeTargetError("no_host", generic)
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise UnsafeTargetError("bad_idna", generic)
    is_ip_literal = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip_literal = False
    if not is_ip_literal:
        if not _HOST_RE.match(host) or host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
            raise UnsafeTargetError("blocked_hostname", generic)
        if host.rsplit(".", 1)[-1].isdigit() or host.rsplit(".", 1)[-1].startswith("0x"):
            raise UnsafeTargetError("numeric_host", generic)   # 2130706433, 0x7f.1, 017700000001…

    try:
        infos = (resolver or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeTargetError("unresolvable", "El dominio no resuelve.")
    ips = sorted({i[4][0].split("%")[0] for i in infos})
    if not ips:
        raise UnsafeTargetError("unresolvable", "El dominio no resuelve.")
    for ip in ips:                                             # TODAS deben ser públicas
        _assert_public(ipaddress.ip_address(ip))

    clean = urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", parts.query, ""))
    return ValidatedUrl(clean, parts.scheme, host, port, tuple(ips))
