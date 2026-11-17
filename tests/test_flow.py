"""Flujo completo contra PostgreSQL real (RLS incluido). Requiere TEST_DATABASE_URL (rol app_rw).
ZAP, SMTP y Redis están simulados (FakeScanner / fakeredis / captura de correos)."""
import os
import re
import socket
import uuid

import fakeredis
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

pytestmark = pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="requiere TEST_DATABASE_URL")

PUBLIC_IP = "93.184.216.34"
EVIL = "<script>alert('xss')</script>"
real_gai = socket.getaddrinfo


@pytest.fixture()
def env(monkeypatch):
    from app.api import admin, auth
    from app.core import ratelimit
    from app.scanner.base import FindingDTO, ScanOutcome
    from app.worker import tasks
    from app.worker.celery_app import celery_app
    from app.main import app

    monkeypatch.setattr(ratelimit, "_r", fakeredis.FakeRedis(decode_responses=True))
    celery_app.conf.task_always_eager = True
    mails = []

    class Mail:
        @staticmethod
        def delay(to, subject, body):
            mails.append((to, body))
    monkeypatch.setattr(auth, "send_email", Mail)
    monkeypatch.setattr(admin, "send_email", Mail)

    class FakeScanner:
        def run(self, req, should_cancel):
            return ScanOutcome(findings=[
                FindingDTO("10038", "CSP no definido", "medium", req.url, evidence=EVIL, method="GET"),
                FindingDTO("10021", "Falta X-Content-Type-Options", "low", req.url)], stats={"urls_discovered": 3})

        def cleanup(self):
            pass
    monkeypatch.setattr(tasks, "ZapScanner", FakeScanner)

    def gai(host, port, *a, **k):
        if host.endswith("cliente.example"):
            ip = "10.0.0.5" if host.startswith("interno.") else PUBLIC_IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real_gai(host, port, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    return TestClient(app), mails


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def onboard(c, mails, email, org=None, invite=None):
    """registro → verificación email → login → alta TOTP → tokens. Devuelve (access, secret)."""
    pw = "S3gura-y-larga-2026"
    body = {"email": email, "password": pw, **({"org_name": org} if org else {}), **({"invite_token": invite} if invite else {})}
    assert c.post("/api/v1/auth/register", json=body).status_code == 202
    if not invite:
        assert c.post("/api/v1/auth/login", json={"email": email, "password": pw}).status_code == 403   # sin verificar
        token = re.search(r"\n\n(\S+)\n", [m for m in mails if m[0] == email][-1][1]).group(1)
        assert c.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 200
    r = c.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    assert r["next"] == "totp_enrollment"
    # el token de enrolamiento NO sirve como access token
    assert c.get("/api/v1/clients", headers=H(r["challenge_token"])).status_code == 401
    secret = c.post("/api/v1/auth/2fa/setup", headers=H(r["challenge_token"])).json()["secret"]
    assert c.post("/api/v1/auth/2fa/confirm", json={"code": "000000"}, headers=H(r["challenge_token"])).status_code == 401
    tokens = c.post("/api/v1/auth/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=H(r["challenge_token"])).json()
    return tokens, secret, pw


def test_full_flow(env):
    c, mails = env
    run = uuid.uuid4().hex[:8]
    admin_t, admin_secret, pw = onboard(c, mails, f"admin-{run}@acme-audit.io", org=f"Acme {run}")
    A = H(admin_t["access_token"])

    # login posterior: contraseña → TOTP; un código ya usado (replay) se rechaza
    ch = c.post("/api/v1/auth/login", json={"email": f"admin-{run}@acme-audit.io", "password": pw}).json()
    assert ch["next"] == "totp"
    assert c.get("/api/v1/clients", headers=H(ch["challenge_token"])).status_code == 401
    import time
    nxt = pyotp.TOTP(admin_secret).at(int(time.time()) + 30)
    assert c.post("/api/v1/auth/2fa/verify", json={"code": nxt}, headers=H(ch["challenge_token"])).status_code == 200
    assert c.post("/api/v1/auth/2fa/verify", json={"code": nxt}, headers=H(ch["challenge_token"])).status_code == 401

    # refresh con rotación y detección de reutilización
    rt1 = admin_t["refresh_token"]
    rt2 = c.post("/api/v1/auth/refresh", json={"refresh_token": rt1}).json()["refresh_token"]
    assert c.post("/api/v1/auth/refresh", json={"refresh_token": rt1}).status_code == 401       # reutilizado
    assert c.post("/api/v1/auth/refresh", json={"refresh_token": rt2}).status_code == 401       # familia revocada

    # Admin: cliente + objetivo; invita a un Auditor
    cl = c.post("/api/v1/clients", headers=A, json={"name": f"Cliente {run}", "contract_ref": "SOW-42",
                "contract_start": "2020-01-01", "contract_end": "2099-12-31"}).json()
    t = c.post(f"/api/v1/clients/{cl['id']}/targets", headers=A, json={"hostname": "app.cliente.example"})
    assert t.status_code == 201 and t.json()["verification"]["name"].startswith("_vulnaudit-verify.")
    assert c.post(f"/api/v1/clients/{cl['id']}/targets", headers=A, json={"hostname": "interno.cliente.example"}).status_code == 422
    assert c.post(f"/api/v1/clients/{cl['id']}/targets", headers=A, json={"hostname": "127.0.0.1"}).status_code == 422
    inv = c.post("/api/v1/users/invitations", headers=A, json={"email": f"aud-{run}@acme-audit.io", "role": "auditor"})
    assert inv.status_code == 201
    inv_token = re.search(r"\n\n(\S+)", [m for m in mails if m[0] == f"aud-{run}@acme-audit.io"][-1][1]).group(1)
    aud_t, _, _ = onboard(c, mails, f"aud-{run}@acme-audit.io", invite=inv_token)
    U = H(aud_t["access_token"])
    aud_id = next(u["id"] for u in c.get("/api/v1/users", headers=A).json() if u["role"] == "auditor" and run in u["email"])

    body = {"client_id": cl["id"], "url": "https://app.cliente.example/", "mode": "passive",
            "consent": {"accepted": True, "statement_version": "2026-01", "authorization_reference": "SOW-42 firmado"}}
    # Roles / visibilidad
    assert c.post("/api/v1/scans", headers=A, json=body).status_code == 403            # Admin no escanea
    assert c.get("/api/v1/clients", headers=U).json() == []                             # auditor sin asignación
    assert c.post("/api/v1/scans", headers=U, json=body).status_code == 404
    assert c.post(f"/api/v1/clients/{cl['id']}/assignments", headers=A, json={"user_id": aud_id}).status_code == 201
    assert c.post("/api/v1/clients", headers=U, json={"name": "x"}).status_code in (403, 422)

    # Denegaciones: SSRF, alcance, consentimiento, modo activo no contratado
    def post(**over):
        b = {**body, **over}
        return c.post("/api/v1/scans", headers=U, json=b)
    assert post(url="http://169.254.169.254/latest/").status_code == 422
    assert post(url="https://interno.cliente.example/").status_code == 422
    assert post(url="https://otra-empresa.example/").status_code in (403, 422)
    assert post(url="https://www.cliente.example/").status_code == 403                  # fuera de alcance
    assert post(consent={**body["consent"], "accepted": False}).status_code == 400
    assert post(consent={**body["consent"], "statement_version": "viejo"}).status_code == 400
    assert post(consent={**body["consent"], "authorization_reference": ""}).status_code == 422
    assert post(mode="active_safe").status_code == 403

    # Escaneo válido (Celery en modo eager con scanner simulado)
    r = post()
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    scan = c.get(f"/api/v1/scans/{scan_id}", headers=U).json()
    assert scan["status"] == "completed" and scan["stats"]["findings_by_severity"] == {"medium": 1, "low": 1}
    f = c.get(f"/api/v1/scans/{scan_id}/findings", headers=U).json()
    assert {x["severity"] for x in f} == {"medium", "low"} and any(x["evidence"] == EVIL for x in f)

    # Reportes: cifrados en disco, descargables, con XSS neutralizado
    reps = c.get(f"/api/v1/scans/{scan_id}/reports", headers=U).json()
    html_rep = next(x for x in reps if x["format"] == "html")
    dl = c.get(f"/api/v1/reports/{html_rep['id']}/download", headers=U)
    assert dl.status_code == 200 and EVIL not in dl.text and "&lt;script&gt;" in dl.text
    assert "sandbox" in dl.headers["content-security-policy"] and "attachment" in dl.headers["content-disposition"]
    from app.core.config import settings
    key = next(__import__("pathlib").Path(settings.reports_dir).rglob(f"{html_rep['id']}.html.enc"))
    assert b"CSP no definido" not in open(key, "rb").read()                             # cifrado en reposo

    # Aislamiento entre organizaciones (capa de aplicación)
    other_t, _, _ = onboard(c, mails, f"admin2-{run}@otra-firma.io", org=f"Otra {run}")
    B = H(other_t["access_token"])
    assert c.get("/api/v1/clients", headers=B).json() == []
    assert c.get(f"/api/v1/scans/{scan_id}", headers=B).status_code == 404
    assert c.get(f"/api/v1/reports/{html_rep['id']}/download", headers=B).status_code == 404
    assert c.get(f"/api/v1/clients/{cl['id']}/targets", headers=B).status_code == 404

    # Trazabilidad: cadena de hashes lineal y acciones esperadas
    logs = c.get("/api/v1/audit-logs?limit=500", headers=A).json()
    actions = {x["action"] for x in logs}
    assert {"scan.created", "scan.denied", "scan.started", "scan.completed", "report.generated",
            "auth.login_success", "client.created", "target.rejected"} <= actions
    assert len(logs) > 10

    # RLS directa en Postgres (aunque el código olvidara filtrar por org)
    eng = create_engine(os.environ["TEST_DATABASE_URL"])
    with eng.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM clients")).scalar() == 0         # sin tenant → nada
        org_b = conn.execute(text("SELECT org_id FROM users WHERE email=:e"), {"e": f"admin2-{run}@otra-firma.io"}).scalar()
        conn.execute(text("SELECT set_config('app.current_org', :o, true)"), {"o": str(org_b)})
        assert conn.execute(text("SELECT count(*) FROM scans WHERE id=:i"), {"i": scan_id}).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM findings")).scalar() == 0
    with eng.begin() as conn:                                                           # cadena de hashes enlazada
        org_a = conn.execute(text("SELECT org_id FROM users WHERE email=:e"), {"e": f"admin-{run}@acme-audit.io"}).scalar()
        conn.execute(text("SELECT set_config('app.current_org', :o, true)"), {"o": str(org_a)})
        rows = conn.execute(text("SELECT prev_hash, entry_hash FROM audit_logs ORDER BY seq")).all()
        assert len(rows) > 10 and rows[0][0] is None
        assert all(rows[i][0] == rows[i - 1][1] for i in range(1, len(rows)))
    with pytest.raises(Exception, match="append-only|permission denied"):
        with eng.begin() as conn:
            conn.execute(text("UPDATE audit_logs SET action='x'"))
