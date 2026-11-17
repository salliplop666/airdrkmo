"""Prueba el adaptador contra una API ZAP simulada (no requiere ZAP)."""
import re

import httpx

from app.scanner import zap as zapmod
from app.scanner.base import ScanRequest
from app.scanner.zap import ZapClient, ZapScanner


def make_fake_zap(log):
    scanners = [{"id": "10", "policyId": "0"}, {"id": "20", "policyId": "2"}, {"id": "30", "policyId": "3"},
                {"id": "40018", "policyId": "4"}, {"id": "40012", "policyId": "4"}, {"id": "90020", "policyId": "4"}]
    alerts = [
        {"pluginId": "10038", "alert": "CSP no definido", "risk": "Medium", "confidence": "High",
         "url": "https://app.example.com/", "method": "GET", "messageId": "7", "cweid": "693",
         "description": "d", "solution": "s", "evidence": ""},
        {"pluginId": "1", "alert": "Fuera de alcance", "risk": "High", "url": "https://other.com/x"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        m = re.match(r"/JSON/(\w+)/(\w+)/(\w+)/", request.url.path)
        comp, kind, name = m.groups()
        log.append((comp, kind, name, dict(request.url.params)))
        assert request.headers["X-ZAP-API-Key"] == "k"
        body = {"Result": "OK"}
        if (comp, name) == ("spider", "scan") or (comp, name) == ("ascan", "scan"):
            body = {"scan": "1"}
        elif name == "status":
            body = {"status": "100"}
        elif name == "recordsToScan":
            body = {"recordsToScan": "0"}
        elif name == "scanners":
            body = {"scanners": scanners}
        elif name == "alerts":
            body = {"alerts": alerts}
        elif name == "message":
            body = {"message": {"requestHeader": "GET / HTTP/1.1\nCookie: sid=SECRET\nHost: x",
                                "responseHeader": "HTTP/1.1 200\nSet-Cookie: a=SECRET"}}
        elif name == "urls":
            body = {"urls": ["https://app.example.com/"]}
        return httpx.Response(200, json=body)
    return handler


def test_active_safe_policy_scope_and_evidence_redaction(monkeypatch):
    monkeypatch.setattr(zapmod, "POLL_SECONDS", 0)
    log = []
    client = ZapClient("http://zap", "k")
    client.http = httpx.Client(base_url="http://zap", headers={"X-ZAP-API-Key": "k"},
                               transport=httpx.MockTransport(make_fake_zap(log)))
    s = ZapScanner(client)
    out = s.run(ScanRequest("sid", "https://app.example.com/", "app.example.com", 443, False, "active_safe"),
                should_cancel=lambda: False)
    s.cleanup()

    enabled = [c for c in log if c[2] == "enableScanners"][0][3]["ids"].split(",")
    assert set(enabled) == {"10", "20", "30", "40012"}          # categoría Injection fuera, salvo la extra explícita
    assert "40018" not in enabled and "90020" not in enabled
    assert any(c[2] == "disableAllScanners" for c in log)       # política fail-closed
    ctx = [c for c in log if c[2] == "includeInContext"][0][3]["regex"]
    assert re.match(ctx, "https://app.example.com/a") and not re.match(ctx, "https://app.example.com.evil.io/")
    assert not re.match(ctx, "https://evil.com/?https://app.example.com/")
    assert len(out.findings) == 1 and out.findings[0].severity == "medium"      # alerta fuera de alcance descartada
    assert "SECRET" not in out.findings[0].evidence and "[REDACTED]" in out.findings[0].evidence
    ua = [c for c in log if c[2] == "setOptionDefaultUserAgent"][0][3]["String"]
    assert "scan=sid" in ua
    assert any(c[2] == "removeContext" for c in log) and any(c[2] == "removeScanPolicy" for c in log)


def test_passive_never_builds_active_policy(monkeypatch):
    monkeypatch.setattr(zapmod, "POLL_SECONDS", 0)
    log = []
    client = ZapClient("http://zap", "k")
    client.http = httpx.Client(base_url="http://zap", transport=httpx.MockTransport(make_fake_zap(log)),
                               headers={"X-ZAP-API-Key": "k"})
    ZapScanner(client).run(ScanRequest("s2", "https://app.example.com/", "app.example.com", 443, False, "passive"),
                           should_cancel=lambda: False)
    assert not any(c[0] == "ascan" for c in log)
