-- VulnAudit · esquema PostgreSQL 15+ (DDL autoritativo de la v0; migra a Alembic después).
-- Aislamiento multi-tenant: columna org_id en toda tabla de datos + Row-Level Security.
-- La app se conecta como `app_rw` (no superusuario, sin BYPASSRLS) y fija
-- `app.current_org` por transacción (ver app/db/session.py).

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
    -- !!! SOLO DESARROLLO: cambia esta contraseña (y DATABASE_URL) en cualquier otro entorno.
    CREATE ROLE app_rw LOGIN PASSWORD 'change-me-dev-only' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

-- ───────────── Identidad ─────────────
CREATE TABLE organizations (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  is_active  boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL REFERENCES organizations(id),
  email              text NOT NULL UNIQUE CHECK (email = lower(email)),
  password_hash      text NOT NULL,                       -- argon2id
  role               text NOT NULL CHECK (role IN ('admin','auditor')),
  is_active          boolean NOT NULL DEFAULT true,
  email_verified_at  timestamptz,
  totp_secret_enc    text,                                -- Fernet
  totp_enabled_at    timestamptz,
  totp_last_step     bigint,                              -- anti-replay de códigos TOTP
  failed_login_count int NOT NULL DEFAULT 0,
  locked_until       timestamptz,
  last_login_at      timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_org_idx ON users(org_id);

CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id),
  email       text NOT NULL CHECK (email = lower(email)),
  role        text NOT NULL CHECK (role IN ('admin','auditor')),
  token_hash  text NOT NULL UNIQUE,                       -- sha256 del token; el token nunca se guarda
  invited_by  uuid NOT NULL REFERENCES users(id),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_verifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id),
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id),
  family_id  uuid NOT NULL,                               -- detección de reutilización (rotación)
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_family_idx ON refresh_tokens(family_id);

-- ───────────── Clientes, alcance y consentimiento ─────────────
CREATE TABLE clients (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         uuid NOT NULL REFERENCES organizations(id),
  name           text NOT NULL,
  legal_name     text,
  contact_email  text,
  contract_ref   text NOT NULL,
  contract_start date NOT NULL,
  contract_end   date NOT NULL,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','terminated')),
  created_by     uuid NOT NULL REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (contract_end >= contract_start),
  UNIQUE (org_id, name)
);

-- Un Auditor solo ve/escanea los clientes que tiene asignados.
CREATE TABLE client_assignments (
  client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id),
  org_id      uuid NOT NULL REFERENCES organizations(id),
  assigned_by uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (client_id, user_id)
);

-- Alcance contratado: dominios que se pueden auditar para cada cliente.
CREATE TABLE targets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              uuid NOT NULL REFERENCES organizations(id),
  client_id           uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  hostname            text NOT NULL CHECK (hostname = lower(hostname)),
  include_subdomains  boolean NOT NULL DEFAULT false,
  active_scan_allowed boolean NOT NULL DEFAULT false,     -- el contrato permite pruebas activas
  verification_token  text NOT NULL,                      -- TXT DNS _vulnaudit-verify.<host>
  verified_at         timestamptz,
  created_by          uuid NOT NULL REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (client_id, hostname)
);

-- Prueba legal de que el auditor confirmó la autorización antes de cada escaneo.
CREATE TABLE consent_records (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                  uuid NOT NULL REFERENCES organizations(id),
  user_id                 uuid NOT NULL REFERENCES users(id),
  client_id               uuid NOT NULL REFERENCES clients(id),
  target_id               uuid NOT NULL REFERENCES targets(id),
  hostname                text NOT NULL,
  mode                    text NOT NULL,
  statement_version       text NOT NULL,
  statement_sha256        text NOT NULL,                  -- hash del texto exacto aceptado
  authorization_reference text NOT NULL,                  -- nº de contrato / SOW / carta de autorización
  ip                      text,
  user_agent              text,
  accepted_at             timestamptz NOT NULL DEFAULT now()
);

-- ───────────── Escaneos, hallazgos y reportes ─────────────
CREATE TABLE scans (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         uuid NOT NULL REFERENCES organizations(id),
  client_id      uuid NOT NULL REFERENCES clients(id),
  target_id      uuid NOT NULL REFERENCES targets(id),
  requested_by   uuid NOT NULL REFERENCES users(id),
  consent_id     uuid NOT NULL REFERENCES consent_records(id),
  target_url     text NOT NULL,
  mode           text NOT NULL CHECK (mode IN ('passive','active_safe')),
  status         text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued','running','completed','failed','cancelled')),
  celery_task_id text,
  resolved_ips   jsonb,                                   -- IPs a las que resolvió el objetivo al escanear
  stats          jsonb,
  error          text,
  queued_at      timestamptz NOT NULL DEFAULT now(),
  started_at     timestamptz,
  finished_at    timestamptz
);
CREATE INDEX scans_org_status_idx ON scans(org_id, status);
CREATE INDEX scans_client_idx ON scans(client_id, queued_at DESC);

CREATE TABLE findings (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL REFERENCES organizations(id),
  scan_id      uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id      text NOT NULL,
  title        text NOT NULL,
  severity     text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  confidence   text,
  url          text NOT NULL,
  method       text,
  param        text,
  cwe_id       int,
  description  text,
  solution     text,
  reference    text,
  evidence_enc text,                                      -- evidencia cifrada (Fernet): es dato del cliente
  fingerprint  text NOT NULL,                             -- sha256(regla|url|método|param) → dedupe y diff entre escaneos
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, fingerprint)
);

CREATE TABLE reports (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id),
  client_id   uuid NOT NULL REFERENCES clients(id),
  scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  format      text NOT NULL CHECK (format IN ('html','pdf')),
  storage_key text NOT NULL UNIQUE,                       -- {org}/{client}/{scan}/{id}.{fmt}.enc
  sha256      text NOT NULL,
  size_bytes  bigint NOT NULL,
  created_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reports_scan_idx ON reports(scan_id);

-- ───────────── Auditoría (append-only + cadena de hashes) ─────────────
CREATE TABLE audit_logs (
  id            uuid PRIMARY KEY,
  seq           bigint GENERATED ALWAYS AS IDENTITY,
  org_id        uuid REFERENCES organizations(id),        -- NULL: eventos previos a identificar tenant
  actor_user_id uuid REFERENCES users(id),
  action        text NOT NULL,
  resource_type text,
  resource_id   text,
  ip            text,
  user_agent    text,
  details       jsonb NOT NULL DEFAULT '{}',
  prev_hash     text,
  entry_hash    text NOT NULL,
  created_at    timestamptz NOT NULL
);
CREATE INDEX audit_org_seq_idx ON audit_logs(org_id, seq DESC);

CREATE FUNCTION audit_logs_immutable() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'audit_logs es append-only'; END $$;
CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();

-- ───────────── Row-Level Security ─────────────
CREATE FUNCTION app_current_org() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.current_org', true), '')::uuid $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['clients','client_assignments','targets','consent_records',
                           'scans','findings','reports'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I
                    USING (org_id = app_current_org())
                    WITH CHECK (org_id = app_current_org())', t);
  END LOOP;
END $$;

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_select ON audit_logs FOR SELECT USING (org_id = app_current_org());
CREATE POLICY audit_insert ON audit_logs FOR INSERT WITH CHECK (true);

-- ───────────── Permisos del rol de la aplicación ─────────────
GRANT USAGE ON SCHEMA public TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rw;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM app_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rw;

-- Al final del archivo schema.sql, agrega esto:

-- 1. Asegurar que el rol app_rw tenga permisos por defecto en futuras tablas/secuencias
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_rw;

-- 2. (Opcional pero recomendado) Crear un índice en el email de users para acelerar logins
-- (Ya tienes UNIQUE, que crea un índice, pero es bueno asegurarse de que sea eficiente)
-- CREATE INDEX IF NOT EXISTS users_email_idx ON users(email); 
-- Nota: El UNIQUE ya lo hace, así que esto es solo informativo.