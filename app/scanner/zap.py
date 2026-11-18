import logging
import re
import time
from typing import Callable

import httpx

from app.core.config import settings
from app.scanner.base import FindingDTO, ScanOutcome, ScanRequest

log = logging.getLogger(__name__)

SAFE_CATEGORIES = {0, 1, 2, 3}

_RISK = {
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}

_REDACT = re.compile(
    r"^(cookie|set-cookie|authorization|proxy-authorization|x-api-key)\s*:.*$",
    re.IGNORECASE | re.MULTILINE,
)

POLL_SECONDS = 5


class ZapClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(
            base_url=self.base_url,
            headers={"X-ZAP-API-Key": api_key},
            timeout=60,
        )

    def call(self, component: str, kind: str, method: str, /, **params) -> dict:
        clean = {
            k: ("true" if v is True else "false" if v is False else str(v))
            for k, v in params.items()
        }
        r = self.http.get(f"/JSON/{component}/{kind}/{method}/", params=clean)
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        try:
            self.http.close()
        except Exception:
            log.exception("Error cerrando cliente HTTP de ZAP")


class ZapScanner:
    def __init__(self, client: ZapClient | None = None):
        self.zap = client or ZapClient(
            settings.zap_url, settings.zap_api_key.get_secret_value()
        )

    @staticmethod
    def _scope_regex(req: ScanRequest) -> str:
        host = re.escape(req.hostname)
        prefix = r"(?:[a-z0-9-]+\.)*" if req.include_subdomains else ""
        port_part = r"(?::80|:443)?" if req.port in (80, 443) else f":{req.port}"
        return rf"^https?://{prefix}{host}{port_part}(?:/.*)?$"

    @staticmethod
    def _wait(
        status_fn: Callable[[], int],
        deadline: float,
        should_cancel: Callable[[], bool],
        stop_fn: Callable[[], None],
        label: str = "tarea",
    ) -> bool:
        last_log = 0.0
        while status_fn() < 100:
            if should_cancel() or time.monotonic() > deadline:
                stop_fn()
                return False
            now = time.monotonic()
            if now - last_log > 30:
                log.info("%s: en progreso", label)
                last_log = now
            time.sleep(POLL_SECONDS)
        return True

    def _build_policy(self, name: str) -> list[int]:
        z = self.zap
        z.call("ascan", "action", "addScanPolicy", scanPolicyName=name)
        z.call("ascan", "action", "disableAllScanners", scanPolicyName=name)
        scanners = z.call("ascan", "view", "scanners", scanPolicyName=name).get("scanners", [])
        ids = {
            int(s["id"])
            for s in scanners
            if int(s.get("policyId", -1)) in SAFE_CATEGORIES
        }
        ids |= set(settings.zap_extra_enabled_rules)
        ids -= set(settings.zap_disabled_rules)
        if ids:
            z.call(
                "ascan", "action", "enableScanners",
                ids=",".join(map(str, sorted(ids))),
                scanPolicyName=name,
            )
        return sorted(ids)

    def run(self, req: ScanRequest, should_cancel: Callable[[], bool]) -> ScanOutcome:
        ctx, policy = f"ctx-{req.scan_id}", f"pol-{req.scan_id}"
        try:
            return self._run(req, should_cancel, ctx, policy)
        finally:
            self._cleanup(ctx, policy)

    def _run(
        self,
        req: ScanRequest,
        should_cancel: Callable[[], bool],
        ctx: str,
        policy: str,
    ) -> ScanOutcome:
        z, out = self.zap, ScanOutcome()
        deadline = time.monotonic() + settings.scan_max_minutes * 60
        scope_re = self._scope_regex(req)

        z.call("core", "action", "newSession", name=f"scan-{req.scan_id}", overwrite=True)
        z.call(
            "core", "action", "setOptionDefaultUserAgent",
            String=f"{settings.scanner_user_agent} scan={req.scan_id}",
        )
        z.call("context", "action", "newContext", contextName=ctx)
        z.call("context", "action", "includeInContext", contextName=ctx, regex=scope_re)
        z.call("context", "action", "setContextInScope", contextName=ctx, booleanInScope=True)
        z.call("pscan", "action", "enableAllScanners")

        spider = z.call(
            "spider", "action", "scan",
            url=req.url, contextName=ctx, subtreeOnly=True, maxChildren=200,
        )["scan"]
        ok = self._wait(
            lambda: int(z.call("spider", "view", "status", scanId=spider)["status"]),
            deadline, should_cancel,
            lambda: z.call("spider", "action", "stop", scanId=spider),
            "spider",
        )

        while ok and int(z.call("pscan", "view", "recordsToScan")["recordsToScan"]) > 0:
            if should_cancel() or time.monotonic() > deadline:
                ok = False
                break
            time.sleep(2)

        if ok and req.mode == "active_safe":
            enabled = self._build_policy(policy)
            out.stats["active_rules_enabled"] = len(enabled)
            z.call("ascan", "action", "setOptionThreadPerHost", Integer=settings.scan_threads_per_host)
            z.call("ascan", "action", "setOptionDelayInMs", Integer=settings.scan_delay_ms)
            z.call(
                "ascan", "action", "setOptionMaxScanDurationInMins",
                Integer=max(1, int((deadline - time.monotonic()) // 60)),
            )
            ascan = z.call(
                "ascan", "action", "scan",
                url=req.url, recurse=True, inScopeOnly=True, scanPolicyName=policy,
            )["scan"]
            ok = self._wait(
                lambda: int(z.call("ascan", "view", "status", scanId=ascan)["status"]),
                deadline, should_cancel,
                lambda: z.call("ascan", "action", "stop", scanId=ascan),
                "ascan",
            )

        out.cancelled = should_cancel()
        if not ok and not out.cancelled:
            out.stats["truncated"] = "max_duration"

        out.findings = self._collect(re.compile(scope_re, re.I))
        out.stats["urls_discovered"] = len(z.call("core", "view", "urls").get("urls", []))
        return out

    def _collect(self, scope: re.Pattern) -> list[FindingDTO]:
        z, findings, start = self.zap, [], 0
        while start < 20000:
            page = z.call("alert", "view", "alerts", start=start, count=500).get("alerts", [])
            for a in page:
                if not scope.match(a.get("url", "")):
                    continue
                sev = _RISK.get(a.get("risk", ""), "info")
                try:
                    cwe = int(str(a.get("cweid", "")).strip())
                    cwe_id = cwe if cwe > 0 else None
                except (ValueError, TypeError):
                    cwe_id = None
                findings.append(FindingDTO(
                    rule_id=str(a.get("pluginId", "")),
                    title=a.get("alert") or a.get("name", "?"),
                    severity=sev,
                    confidence=a.get("confidence"),
                    url=a.get("url", ""),
                    method=a.get("method") or None,
                    param=a.get("param") or None,
                    cwe_id=cwe_id,
                    description=a.get("description"),
                    solution=a.get("solution"),
                    reference=a.get("reference"),
                    evidence=self._evidence(a, enrich=sev != "info" and len(findings) < 300),
                ))
            if len(page) < 500:
                break
            start += 500
        return findings

    def _evidence(self, alert: dict, enrich: bool) -> str | None:
        parts = []
        for label, key in (("Evidencia", "evidence"), ("Payload", "attack"), ("Otros", "other")):
            if alert.get(key):
                parts.append(f"{label}: {alert[key]}")
        if enrich and alert.get("messageId"):
            try:
                m = self.zap.call("core", "view", "message", id=alert["messageId"])["message"]
                parts.append(
                    "--- Petición ---\n"
                    + _REDACT.sub(r"\1: [REDACTED]", m.get("requestHeader", ""))[:1500]
                )
                parts.append(
                    "--- Respuesta ---\n"
                    + _REDACT.sub(r"\1: [REDACTED]", m.get("responseHeader", ""))[:1500]
                )
            except Exception:
                log.warning("No se pudo obtener el mensaje %s", alert.get("messageId"))
        return "\n".join(parts)[:6000] or None

    def _cleanup(self, ctx: str | None, policy: str | None) -> None:
        try:
            if policy:
                self.zap.call("ascan", "action", "removeScanPolicy", scanPolicyName=policy)
            if ctx:
                self.zap.call("context", "action", "removeContext", contextName=ctx)
            self.zap.call("core", "action", "newSession", name="idle", overwrite=True)
        except Exception:
            log.exception("Fallo limpiando ZAP")

    def cleanup(self) -> None:
        self.zap.close()
