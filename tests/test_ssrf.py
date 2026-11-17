import socket

import pytest

from app.core.ssrf import UnsafeTargetError, validate_public_url

PORTS = [80, 443, 8080, 8443]


def fake(mapping):
    def resolver(host, port, **kw):
        ips = mapping[host]
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    return resolver


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://10.0.0.5/", "http://192.168.1.1/",
    "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data/", "http://0.0.0.0/",
    "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/", "http://[fd00::1]/",
    "http://2130706433/", "http://0x7f.1/", "http://017700000001/",      # formas numéricas de 127.0.0.1
    "http://foo.internal/", "http://printer.local/", "http://user:pw@example.com/",
    "http://evil.com\\@127.0.0.1/", "ftp://example.com/", "file:///etc/passwd", "gopher://x/", "",
    "http://example.com:22/", "http://example.com:6379/", "http://example.com:99999/",
])
def test_blocked(url):
    with pytest.raises(UnsafeTargetError):
        validate_public_url(url, allowed_ports=PORTS)


def test_domain_resolving_to_private_is_blocked():
    with pytest.raises(UnsafeTargetError) as e:
        validate_public_url("https://rebind.example.com/", allowed_ports=PORTS,
                            resolver=fake({"rebind.example.com": ["10.1.2.3"]}))
    assert e.value.code == "non_public_ip"


def test_mixed_records_are_blocked():
    # basta UN registro privado entre varios públicos
    with pytest.raises(UnsafeTargetError):
        validate_public_url("https://mixed.example.com/", allowed_ports=PORTS,
                            resolver=fake({"mixed.example.com": ["93.184.216.34", "127.0.0.1"]}))


def test_public_ok_and_normalized():
    v = validate_public_url("HTTPS://Example.COM:8443/app?x=1#frag", allowed_ports=PORTS,
                            resolver=fake({"example.com": ["93.184.216.34"]}))
    assert (v.hostname, v.port, v.url) == ("example.com", 8443, "https://example.com:8443/app?x=1")
    assert v.resolved_ips == ("93.184.216.34",)
