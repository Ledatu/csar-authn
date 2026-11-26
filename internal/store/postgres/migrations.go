package postgres

import (
	"context"

	"github.com/ledatu/csar-core/pgutil"
)

var migrations = []pgutil.Migration{
	{
		Name: "001_initial",
		Up: `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    avatar_url   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email            TEXT NOT NULL DEFAULT '',
    display_name     TEXT NOT NULL DEFAULT '',
    avatar_url       TEXT NOT NULL DEFAULT '',
    access_token     TEXT NOT NULL DEFAULT '',
    refresh_token    TEXT NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ,
    linked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id);
`,
	},
	{
		Name: "002_sts_jti_log",
		Up: `
CREATE TABLE IF NOT EXISTS sts_jti_log (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sts_jti_log_expires_at ON sts_jti_log (expires_at);
`,
	},
	{
		Name: "003_sts_jti_log_add_issuer",
		Up: `
ALTER TABLE sts_jti_log ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE sts_jti_log DROP CONSTRAINT IF EXISTS sts_jti_log_pkey;
ALTER TABLE sts_jti_log ADD PRIMARY KEY (issuer, jti);
`,
	},
	{
		Name: "004_account_linking",
		Up: `
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
`,
	},
	{
		Name: "005_telegram_support",
		Up: `
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
DROP INDEX IF EXISTS idx_users_email_lower;
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email)) WHERE email IS NOT NULL AND email != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users (phone) WHERE phone IS NOT NULL AND phone != '';
`,
	},
	{
		Name: "006_service_accounts",
		Up: `
CREATE TABLE IF NOT EXISTS service_accounts (
    name                TEXT PRIMARY KEY,
    public_key_pem      TEXT NOT NULL,
    allowed_audiences   TEXT[] NOT NULL DEFAULT '{}',
    allow_all_audiences BOOLEAN NOT NULL DEFAULT false,
    token_ttl           INTERVAL NOT NULL DEFAULT '1 hour',
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);
`,
	},
	{
		Name: "007_sessions",
		Up: `
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    user_agent   TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE revoked_at IS NULL;
`,
	},
	{
		Name: "008_account_merge",
		Up: `
ALTER TABLE users ADD COLUMN IF NOT EXISTS merged_into UUID REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS merged_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS merge_records (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash         TEXT NOT NULL UNIQUE,
    source_user        UUID NOT NULL REFERENCES users(id),
    target_user        UUID NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ,
    authz_completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_merge_records_pending
    ON merge_records (consumed_at) WHERE authz_completed_at IS NULL;
`,
	},
	{
		Name: "009_provider_metadata",
		Up:   `ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS provider_metadata JSONB;`,
	},
	{
		Name: "010_bot_verifications",
		Up: `
CREATE TABLE IF NOT EXISTS bot_verifications (
    id               UUID PRIMARY KEY,
    code_hash        VARCHAR(64) NOT NULL,
    intent           VARCHAR(20) NOT NULL,
    user_id          UUID REFERENCES users(id),
    provider         VARCHAR(50),
    provider_user_id VARCHAR(255),
    provider_display VARCHAR(255),
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    confirmed_at     TIMESTAMPTZ,
    consumed_at      TIMESTAMPTZ,
    user_agent       TEXT,
    ip_address       TEXT
);
CREATE INDEX IF NOT EXISTS idx_bot_verifications_code_hash
    ON bot_verifications (code_hash) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_bot_verifications_expires
    ON bot_verifications (expires_at) WHERE status IN ('pending', 'confirmed');
`,
	},
	{
		Name: "011_passkeys",
		Up: `
CREATE TABLE IF NOT EXISTS passkeys (
    id                               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label                            TEXT NOT NULL,
    credential_id                    BYTEA NOT NULL UNIQUE,
    public_key                       BYTEA NOT NULL,
    attestation_type                 TEXT NOT NULL DEFAULT '',
    transports                       TEXT[] NOT NULL DEFAULT '{}',
    user_present                     BOOLEAN NOT NULL DEFAULT false,
    user_verified                    BOOLEAN NOT NULL DEFAULT false,
    backup_eligible                  BOOLEAN NOT NULL DEFAULT false,
    backup_state                     BOOLEAN NOT NULL DEFAULT false,
    aaguid                           BYTEA NOT NULL DEFAULT '',
    sign_count                       BIGINT NOT NULL DEFAULT 0,
    attachment                       TEXT NOT NULL DEFAULT '',
    attestation_client_data_json     BYTEA NOT NULL DEFAULT '',
    attestation_client_data_hash     BYTEA NOT NULL DEFAULT '',
    attestation_authenticator_data   BYTEA NOT NULL DEFAULT '',
    attestation_object               BYTEA NOT NULL DEFAULT '',
    attestation_public_key_algorithm BIGINT NOT NULL DEFAULT 0,
    created_at                       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at                     TIMESTAMPTZ,
    updated_at                       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys (user_id);

CREATE TABLE IF NOT EXISTS passkey_challenges (
    id           UUID PRIMARY KEY,
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('registration', 'login')),
    session_data JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires
    ON passkey_challenges (expires_at) WHERE consumed_at IS NULL;
`,
	},
	{
		Name: "012_login_handoffs",
		Up: `
CREATE TABLE IF NOT EXISTS login_handoffs (
    id                  UUID PRIMARY KEY,
    scan_token_hash     VARCHAR(64) NOT NULL UNIQUE,
    desktop_secret_hash VARCHAR(64) NOT NULL,
    redirect_url        TEXT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    approved_by_user_id UUID REFERENCES users(id),
    desktop_user_agent  TEXT NOT NULL DEFAULT '',
    desktop_ip_address  TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    approved_at         TIMESTAMPTZ,
    denied_at           TIMESTAMPTZ,
    consumed_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_login_handoffs_pending_scan
    ON login_handoffs (scan_token_hash) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_login_handoffs_pending_ip
    ON login_handoffs (desktop_ip_address) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_login_handoffs_expires
    ON login_handoffs (expires_at) WHERE status IN ('pending', 'approved');
`,
	},
	{
		Name: "013_user_attribution_touches",
		Up: `
CREATE TABLE IF NOT EXISTS attribution_touches (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_type     TEXT NOT NULL,
    source_key      TEXT NOT NULL,
    source_metadata JSONB,
    touched_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    replaced_by     UUID REFERENCES attribution_touches(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_user_attribution_touches_user_active
    ON attribution_touches (user_id, touched_at DESC)
    WHERE replaced_by IS NULL AND consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_attribution_touches_expires
    ON attribution_touches (expires_at)
    WHERE replaced_by IS NULL AND consumed_at IS NULL;
`,
	},
	{
		Name: "014_user_avatar_storage_key",
		Up: `
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_storage_key TEXT NOT NULL DEFAULT '';
`,
	},
	{
		Name: "015_user_avatar_variant_storage_keys",
		Up: `
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_preview_storage_key TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_master_storage_key TEXT NOT NULL DEFAULT '';
`,
	},
	{
		Name: "016_email_otp_challenges",
		Up: `
CREATE TABLE IF NOT EXISTS email_otp_challenges (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   VARCHAR(64) NOT NULL,
    intent      VARCHAR(20) NOT NULL CHECK (intent IN ('login', 'link')),
    user_id     UUID REFERENCES users(id),
    status      VARCHAR(20) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'consumed', 'expired')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    user_agent  TEXT NOT NULL DEFAULT '',
    ip_address  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_pending_id
    ON email_otp_challenges (id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_pending_email
    ON email_otp_challenges (email, created_at DESC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_pending_ip
    ON email_otp_challenges (ip_address) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_expires
    ON email_otp_challenges (expires_at) WHERE status = 'pending';
`,
	},
	{
		Name: "017_email_canonical",
		Up: `
UPDATE users
   SET email = lower(trim(email))
 WHERE email IS NOT NULL
   AND email <> '';

UPDATE oauth_accounts
   SET email = lower(trim(email))
 WHERE email <> '';

UPDATE oauth_accounts
   SET provider_user_id = lower(trim(provider_user_id))
 WHERE provider = 'email';

UPDATE email_otp_challenges
   SET email = lower(trim(email));

ALTER TABLE oauth_accounts
  ADD CONSTRAINT chk_oauth_email_provider_user_id_lower
  CHECK (provider <> 'email' OR provider_user_id = lower(provider_user_id));
`,
	},
	{
		Name: "018_impersonation",
		Up: `
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS impersonator_user_id UUID REFERENCES users(id);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS impersonation_reason TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS impersonation_grants (
    id             UUID PRIMARY KEY,
    token_hash     VARCHAR(64) NOT NULL UNIQUE,
    admin_user_id  UUID NOT NULL REFERENCES users(id),
    target_user_id UUID NOT NULL REFERENCES users(id),
    reason         TEXT NOT NULL,
    redirect_url   TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_impersonation_grants_expires
    ON impersonation_grants (expires_at) WHERE consumed_at IS NULL;
`,
	},
	{
		Name: "019_seller_api_credentials",
		Up: `
CREATE TABLE IF NOT EXISTS seller_api_credentials (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id),
    seller_id TEXT NOT NULL,
    label TEXT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_seller_api_credentials_owner
  ON seller_api_credentials (owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_seller_api_credentials_active
  ON seller_api_credentials (owner_user_id, expires_at)
  WHERE revoked_at IS NULL;
`,
	},
	{
		Name: "020_service_account_lifecycle",
		Up: `
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS reactivated_at TIMESTAMPTZ;
`,
	},
	{
		Name: "021_seller_api_credential_scopes",
		Up: `
-- Existing rows and legacy writers retain exactly advert-read authority.
ALTER TABLE seller_api_credentials
  ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT ARRAY['adverts:read']::TEXT[];
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
    WHERE conrelid = 'seller_api_credentials'::regclass
      AND conname = 'seller_api_credentials_scopes_check') THEN
    ALTER TABLE seller_api_credentials ADD CONSTRAINT seller_api_credentials_scopes_check
      CHECK (cardinality(scopes) BETWEEN 1 AND 2
        AND array_position(scopes, NULL) IS NULL
        AND scopes <@ ARRAY['adverts:read', 'analytics:read']::TEXT[]
        AND (cardinality(scopes) = 1 OR scopes[1] <> scopes[2]));
  END IF;
END $$;
`,
	},
	{
		Name: "022_seller_api_advertising_scope",
		Up: `
-- Expand only the consent vocabulary. Never rewrite existing grants or defaults.
ALTER TABLE seller_api_credentials DROP CONSTRAINT IF EXISTS seller_api_credentials_scopes_check;
ALTER TABLE seller_api_credentials ADD CONSTRAINT seller_api_credentials_scopes_check
  CHECK (cardinality(scopes) BETWEEN 1 AND 3
    AND array_position(scopes, NULL) IS NULL
    AND scopes <@ ARRAY['adverts:read', 'analytics:read', 'advertising:read']::TEXT[]
    AND cardinality(scopes) =
      (CASE WHEN 'adverts:read' = ANY(scopes) THEN 1 ELSE 0 END
       + CASE WHEN 'analytics:read' = ANY(scopes) THEN 1 ELSE 0 END
       + CASE WHEN 'advertising:read' = ANY(scopes) THEN 1 ELSE 0 END));
`,
	},
	{Name: "023_hosted_seller_mcp", Up: `
CREATE TABLE seller_mcp_requests (
 id text PRIMARY KEY, browser_hash text NOT NULL, client_id text NOT NULL, redirect_uri text NOT NULL,
 challenge text NOT NULL, state text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX seller_mcp_requests_expiry ON seller_mcp_requests(expires_at);
CREATE TABLE seller_mcp_grants (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 seller_id uuid NOT NULL, client_id text NOT NULL, redirect_uri text NOT NULL, challenge text NOT NULL,
 code_hash text UNIQUE, code_expires_at timestamptz NOT NULL, access_hash text UNIQUE,
 expires_at timestamptz NOT NULL
);
CREATE INDEX seller_mcp_grants_owner ON seller_mcp_grants(owner_id);
CREATE INDEX seller_mcp_grants_expiry ON seller_mcp_grants(expires_at);
CREATE TABLE seller_mcp_delegations (
 token_hash text PRIMARY KEY, grant_id uuid NOT NULL REFERENCES seller_mcp_grants(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE INDEX seller_mcp_delegations_expiry ON seller_mcp_delegations(expires_at);
CREATE INDEX seller_mcp_delegations_grant ON seller_mcp_delegations(grant_id);
`},
	{Name: "024_mcp_campaign_selection", Up: `
ALTER TABLE seller_mcp_delegations ADD COLUMN discovery_only boolean NOT NULL DEFAULT false, ADD COLUMN report_seller uuid;
ALTER TABLE seller_mcp_grants ALTER COLUMN seller_id DROP NOT NULL,
 ADD COLUMN all_campaigns boolean NOT NULL DEFAULT false,
 ADD COLUMN selected_ids text[] NOT NULL DEFAULT '{}',
 ADD CONSTRAINT mcp_selection_shape CHECK (
 (seller_id IS NOT NULL AND NOT all_campaigns AND cardinality(selected_ids)=0) OR
 (seller_id IS NULL AND all_campaigns AND cardinality(selected_ids)=0) OR
 (seller_id IS NULL AND NOT all_campaigns AND cardinality(selected_ids) BETWEEN 2 AND 256));
`},
	{Name: "025_mcp_refresh_sessions", Up: `
ALTER TABLE seller_mcp_grants ADD COLUMN session_access_hash text UNIQUE, ADD COLUMN access_expires_at timestamptz;
CREATE TABLE seller_mcp_refresh_tokens (
 token_hash text PRIMARY KEY, grant_id uuid NOT NULL REFERENCES seller_mcp_grants(id) ON DELETE CASCADE, spent boolean NOT NULL DEFAULT false
);
CREATE INDEX seller_mcp_refresh_grant ON seller_mcp_refresh_tokens(grant_id);
CREATE UNIQUE INDEX seller_mcp_refresh_current ON seller_mcp_refresh_tokens(grant_id) WHERE NOT spent;
`},
	{Name: "026_caller_registry", Up: `
CREATE TABLE registered_callers (
 id uuid PRIMARY KEY, owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 caller_kind text NOT NULL CHECK (caller_kind IN ('agent','application')),
 label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 80),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
 UNIQUE(owner_user_id,id)
);
CREATE INDEX registered_callers_active_owner ON registered_callers(owner_user_id,created_at DESC) WHERE revoked_at IS NULL;
`},
	{Name: "027_caller_credential_bindings", Up: `
CREATE TABLE registered_caller_credentials (
 credential_kind text NOT NULL CHECK(credential_kind IN ('api_key','oauth_access')),
 credential_id text NOT NULL CHECK(char_length(credential_id) BETWEEN 1 AND 256),
 caller_id uuid NOT NULL, owner_user_id uuid NOT NULL,
 PRIMARY KEY(credential_kind,credential_id),
 FOREIGN KEY(owner_user_id,caller_id) REFERENCES registered_callers(owner_user_id,id) ON DELETE CASCADE
);
CREATE INDEX registered_caller_credentials_caller ON registered_caller_credentials(caller_id);
`},
	{Name: "028_mcp_dynamic_clients", Up: `
CREATE TABLE seller_mcp_clients (
 client_id text PRIMARY KEY, fingerprint text NOT NULL UNIQUE,
 metadata jsonb NOT NULL CHECK(octet_length(metadata::text)<=65536),
 created_at timestamptz NOT NULL DEFAULT now(), approved_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours'
);
CREATE INDEX seller_mcp_clients_unapproved ON seller_mcp_clients(expires_at) WHERE approved_at IS NULL;
ALTER TABLE seller_mcp_requests ADD COLUMN client_name text NOT NULL DEFAULT '',
 ADD COLUMN refresh_allowed boolean NOT NULL DEFAULT true;
ALTER TABLE seller_mcp_grants ADD COLUMN client_name text NOT NULL DEFAULT '';
`},
	{Name: "029_mcp_last_used", Up: `ALTER TABLE seller_mcp_grants ADD COLUMN last_used_at timestamptz;`},
	{Name: "030_universal_credentials", Up: `
CREATE TABLE credential_grants (
 id uuid PRIMARY KEY,
 schema_version smallint NOT NULL CHECK(schema_version=1),
 owner_user_id uuid NOT NULL,
 caller_id uuid NOT NULL,
 credential_kind text NOT NULL CHECK(credential_kind IN ('api_key','oauth_access')),
 constraints jsonb NOT NULL CHECK((
   jsonb_typeof(constraints)='object' AND octet_length(constraints::text)<=131072
   AND constraints->>'version'='1'
   AND jsonb_typeof(constraints->'scopes')='array'
   AND jsonb_array_length(constraints->'scopes') BETWEEN 1 AND 32
   AND jsonb_typeof(constraints->'namespaces')='array'
   AND jsonb_array_length(constraints->'namespaces') BETWEEN 1 AND 16
   AND jsonb_typeof(constraints->'selection')='object'
   AND constraints->'selection'->>'mode' IN ('selected','current_and_future')
   AND CASE WHEN constraints->'selection'->>'mode'='selected' THEN
     jsonb_typeof(constraints->'selection'->'resources')='array'
     AND jsonb_array_length(constraints->'selection'->'resources') BETWEEN 1 AND 256
     ELSE coalesce(jsonb_array_length(constraints->'selection'->'resources'),0)=0 END) IS TRUE),
 client_binding jsonb CHECK(client_binding IS NULL OR
   (jsonb_typeof(client_binding)='object' AND octet_length(client_binding::text)<=8192 AND credential_kind='oauth_access')),
 label text NOT NULL CHECK(octet_length(label)<=320),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 revoked_at timestamptz,
 last_used_at timestamptz,
 FOREIGN KEY(owner_user_id,caller_id) REFERENCES registered_callers(owner_user_id,id)
);
CREATE INDEX credential_grants_owner ON credential_grants(owner_user_id,credential_kind,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX credential_grants_caller ON credential_grants(caller_id,revoked_at);
CREATE TABLE credential_secrets (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL REFERENCES credential_grants(id),
 purpose text NOT NULL CHECK(purpose IN ('access','authorization_code','refresh','exchange','discovery','resource')),
 format_version smallint NOT NULL CHECK(format_version=1),
 token_hash char(64) NOT NULL UNIQUE CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 spent_at timestamptz,
 resource_ref jsonb CHECK((purpose='resource' AND resource_ref IS NOT NULL AND jsonb_typeof(resource_ref)='object' AND octet_length(resource_ref::text)<=1024)
   OR (purpose<>'resource' AND resource_ref IS NULL)),
 parent_secret_id uuid,
 UNIQUE(grant_id,id),
 FOREIGN KEY(grant_id,parent_secret_id) REFERENCES credential_secrets(grant_id,id),
 CHECK(parent_secret_id IS NULL OR parent_secret_id<>id)
);
CREATE INDEX credential_secrets_grant ON credential_secrets(grant_id,purpose,spent_at);
CREATE INDEX credential_secrets_expiry ON credential_secrets(expires_at);
CREATE UNIQUE INDEX credential_secrets_current_refresh ON credential_secrets(grant_id) WHERE purpose='refresh' AND spent_at IS NULL;
CREATE TABLE credential_authorization_requests (
 id text PRIMARY KEY CHECK(octet_length(id) BETWEEN 1 AND 128),
 schema_version smallint NOT NULL CHECK(schema_version=1),
 browser_hash char(64) NOT NULL CHECK(browser_hash ~ '^[0-9a-f]{64}$'),
 client_binding jsonb NOT NULL CHECK(jsonb_typeof(client_binding)='object' AND octet_length(client_binding::text)<=8192),
 profile_id text NOT NULL CHECK(octet_length(profile_id) BETWEEN 1 AND 128),
 profile_revision numeric(20,0) NOT NULL CHECK(profile_revision BETWEEN 1 AND 18446744073709551615),
 audience text NOT NULL CHECK(octet_length(audience) BETWEEN 1 AND 512),
 scopes jsonb NOT NULL CHECK(jsonb_typeof(scopes)='array' AND jsonb_array_length(scopes) BETWEEN 1 AND 32),
 namespaces jsonb NOT NULL CHECK(jsonb_typeof(namespaces)='array' AND jsonb_array_length(namespaces) BETWEEN 1 AND 16),
 state text NOT NULL CHECK(octet_length(state)<=2048),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 consumed_at timestamptz
);
CREATE INDEX credential_requests_expiry ON credential_authorization_requests(expires_at,consumed_at);
CREATE INDEX credential_requests_browser ON credential_authorization_requests(browser_hash,((client_binding->>'client_id')));
CREATE FUNCTION protect_credential_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='credential_grants' THEN
   IF (to_jsonb(NEW)-'revoked_at'-'last_used_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at'-'last_used_at')
      OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
     RAISE EXCEPTION 'immutable credential authority';
   END IF;
 ELSE
   IF (to_jsonb(NEW)-'spent_at') IS DISTINCT FROM (to_jsonb(OLD)-'spent_at')
      OR (OLD.spent_at IS NOT NULL AND NEW.spent_at IS DISTINCT FROM OLD.spent_at) THEN
     RAISE EXCEPTION 'immutable credential secret or request';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER credential_grant_authority BEFORE UPDATE ON credential_grants FOR EACH ROW EXECUTE FUNCTION protect_credential_authority();
CREATE TRIGGER credential_secret_authority BEFORE UPDATE ON credential_secrets FOR EACH ROW EXECUTE FUNCTION protect_credential_authority();
-- Requests use the same one-way state guard, with their own column name.
CREATE FUNCTION protect_credential_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'consumed_at') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_at')
    OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) THEN
   RAISE EXCEPTION 'immutable credential request';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER credential_request_authority BEFORE UPDATE ON credential_authorization_requests FOR EACH ROW EXECUTE FUNCTION protect_credential_request();
`},
}

// runMigrations applies pending schema migrations using the shared runner.
func (s *Store) runMigrations(ctx context.Context) error {
	return pgutil.RunMigrations(ctx, s.pool, "schema_migrations", migrations, s.logger)
}
