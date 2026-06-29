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
}

// runMigrations applies pending schema migrations using the shared runner.
func (s *Store) runMigrations(ctx context.Context) error {
	return pgutil.RunMigrations(ctx, s.pool, "schema_migrations", migrations, s.logger)
}
