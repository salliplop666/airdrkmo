# VulnAudit — plataforma SaaS de auditoría web para clientes con contrato

FastAPI · PostgreSQL (RLS) · Redis/Celery · OWASP ZAP · WeasyPrint

## Puesta en marcha (desarrollo)
```bash
cp .env.example .env     # rellena JWT_SECRET, DATA_ENCRYPTION_KEY y ZAP_API_KEY (comandos dentro del archivo)
docker compose up --build
# API:  http://localhost:8000/docs   ·   Correos de prueba (MailHog): http://localhost:8025
```
Pruebas: `pip install -r requirements.txt && pytest` (las de BD requieren `TEST_DATABASE_URL` apuntando
a una BD con `sql/schema.sql` cargado, conectando como `app_rw`).

## Flujo de uso
1. `POST /auth/register` (crea organización + primer Admin) → llega token por email → `POST /auth/verify-email`.
2. `POST /auth/login` → `challenge_token`. Primera vez: `POST /auth/2fa/setup` (QR TOTP) + `/2fa/confirm`.
   Siguientes: `POST /auth/2fa/verify`. Solo entonces se emiten access/refresh tokens.
3. Admin: `POST /clients` (contrato y vigencia) → `POST /clients/{id}/targets` (alcance) → publica el TXT DNS
   → `POST /targets/{id}/verify` → `POST /users/invitations` → `POST /clients/{id}/assignments`.
4. Auditor: `GET /scans/consent-statement` → `POST /scans` con la URL, el modo y el consentimiento.
5. El worker escanea; al terminar genera HTML+PDF cifrados. `GET /reports/{id}/download` (auditado).

## Decisiones de seguridad (y dónde están)
| Requisito | Implementación |
|---|---|
| Auth fuerte | argon2id, verificación de email obligatoria, TOTP obligatorio con anti-replay, tokens con *scope* (`enroll`/`mfa`/`access`), refresh con rotación y detección de reutilización, bloqueo y rate-limit — `api/auth.py`, `core/security.py` |
| Multi-tenant | `org_id` en todo + **RLS de Postgres** (`sql/schema.sql`) con rol `app_rw` sin BYPASSRLS; tenant fijado por transacción (`db/session.py`); auditor solo ve clientes asignados |
| Separación de funciones | Admin gestiona clientes/alcance/usuarios y no escanea; Auditor escanea solo sus clientes |
| Consentimiento | declaración versionada, renderizada en servidor; se guarda hash del texto, referencia del contrato, usuario, IP y fecha (`consent_records`); además verificación DNS TXT del dominio |
| Alcance | la URL debe caer en un `target` del cliente y el contrato debe estar vigente (se re-valida en el worker) |
| SSRF | `core/ssrf.py`: esquema, puertos, sin userinfo, sin formas numéricas de IP, resolución DNS y **todas** las IPs públicas; se repite antes de escanear |
| No destructivo | `passive` por defecto; `active_safe` solo con permiso explícito en el target, categorías no intrusivas (fail-closed), baja presión, duración máxima, UA identificable y *kill switch* |
| Trazabilidad | `audit_logs` append-only (trigger) con cadena de hashes por organización; también se registran los intentos **denegados** |
| Datos sensibles | evidencias y secretos TOTP cifrados (Fernet) en BD; reportes cifrados en disco con SHA-256; descarga auditada |
| Reportes | Jinja2 con autoescape total (la evidencia viene del objetivo), WeasyPrint sin recursos externos, descarga con `sandbox` CSP |

## ⚠️ Endurecimiento obligatorio antes de producción
1. **Egreso de red del escáner.** Quien hace las peticiones es ZAP y resuelve DNS por su cuenta
   (rebinding, redirects). La validación de la app no basta: bloquea en el host el tráfico de la red
   `scanner_net` hacia rangos privados (o fuerza ZAP a salir por un proxy de egreso, p. ej. Smokescreen):
   ```bash
   SN=172.31.200.0/24
   for r in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8 100.64.0.0/10; do
     iptables -I DOCKER-USER -s $SN -d $r -j REJECT; done
   iptables -I DOCKER-USER -s $SN -d $SN -j ACCEPT      # tráfico interno worker↔ZAP (debe quedar primero)
   # + equivalente ip6tables
   ```
2. **IDs de reglas ZAP.** `active_safe` parte de las categorías 0–3 de la política de ZAP (excluye *Injection*)
   más `ZAP_EXTRA_ENABLED_RULES`. Verifica en tu versión con `ascan/view/scanners`; los IDs habilitados
   quedan en `scans.stats.active_rule_ids`. Ningún escáner activo garantiza «no destructivo»: prefiere staging.
3. **Aislamiento entre clientes en ZAP.** Hay un ZAP con concurrencia 1 y sesión borrada tras cada escaneo.
   Para escalar, un ZAP efímero por escaneo (Kubernetes Job) en lugar de uno compartido.
4. Cambiar la contraseña de `app_rw`, TLS en todo (API, Postgres, SMTP), secretos en un gestor
   (KMS/Vault) con rotación de `DATA_ENCRYPTION_KEY`, `ENV=production`, uvicorn tras proxy con `--forwarded-allow-ips`.
5. Almacenamiento de reportes en S3/MinIO con SSE + versionado en lugar de volumen local.

## Pendiente (hoja de ruta)
Códigos de recuperación 2FA · Alembic (hoy `sql/schema.sql` es la fuente) · adaptador `nuclei`
(implementar `scanner.base.Scanner`) · escaneos autenticados · programación recurrente · diff entre escaneos
(`findings.fingerprint`) · verificación periódica del hash-chain · SSO/WebAuthn · front-end.
