# csar-authn

## Explicit origin issuer ingress peer

`origin_router_peer_cn` optionally configures the exact verified gateway leaf CN
for the origin issuer, paired with `origin_router_ca_file`. Both are startup-only.
The generic registration path requires an explicit peer and a dedicated root;
omitted configuration preserves the existing origin/MCP compatibility peer.
Multiple issuer features may share a dedicated CA/listener, but each checks its
own CA/peer pair and cannot adopt another feature's allowed peer. General service
trust never becomes dedicated issuer trust through the registration cache.
Conversely, a dedicated issuer root cannot enter the general personal-key
introspection receiver by presenting the same client CN.

Changing peer or credential-profile configuration requires restart before any
reload mutation. This source change does not rotate certificates or JWT keys,
enable generic credential issuance, alter outbound Telegram-ID JWT signing, or
publish deployment configuration.

A standalone OAuth authentication service for the [**csar**](https://github.com/ledatu/csar) platform. It handles multi-provider OAuth login via [Goth](https://github.com/markbates/goth), maps social identities to internal user UUIDs stored in PostgreSQL, issues signed JWT session tokens, and exposes a JWKS endpoint so the csar router can validate sessions independently.

## Features

- **Multi-provider OAuth** — Google, GitHub, and Discord out of the box (easily extensible via Goth)
- **JWT session tokens** — RS256, ES256, or EdDSA; stored in an `HttpOnly` cookie
- **JWKS endpoint** — `/.well-known/jwks.json` for downstream JWT verification
- **Auto key generation** — generates and persists a signing key pair on first boot if none is provided
- **PostgreSQL-backed identity store** — maps provider identities to stable internal user UUIDs
- **Automatic schema migrations** — runs on startup, no external migration tool required
- **Graceful shutdown** — drains in-flight requests before exiting

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/{provider}` | Initiate OAuth login (`provider`: `google`, `github`, `discord`) |
| `GET` | `/auth/{provider}/callback` | OAuth callback; sets session cookie on success |
| `POST` | `/auth/logout` | Clear the session cookie |
| `GET` | `/auth/me` | Return the current user's profile and linked accounts |
| `GET` | `/.well-known/jwks.json` | Public key set for JWT verification |
| `GET` | `/health` | Health check (`{"status":"ok"}`) |

## Getting Started

### Prerequisites

- Go 1.21+
- PostgreSQL
- OAuth app credentials for each provider you want to enable

### Installation

```bash
git clone https://github.com/ledatu/csar-authn.git
cd csar-authn
go mod download
```

### Configuration

Copy the example config and fill in your values:

```bash
cp config.example.yaml config.yaml
```

The key fields to set:

```yaml
listen_addr: ":8081"
base_url: "http://localhost:8081"       # Used to build OAuth redirect URIs
frontend_url: "http://localhost:3000"   # Redirect destination after login

database:
  driver: "postgres"
  dsn: "postgres://user:pass@localhost:5432/csar_auth?sslmode=disable"

jwt:
  algorithm: "RS256"   # RS256 | ES256 | EdDSA
  issuer: "http://localhost:8081"
  audience: "csar-api"
  ttl: "24h"
  auto_generate: true  # Generate keys on first boot
  key_dir: "./keys"    # Where keys are persisted

oauth:
  session_secret: "<random-string>"
  providers:
    - name: "google"
      client_id: "<GOOGLE_CLIENT_ID>"
      client_secret: "<GOOGLE_CLIENT_SECRET>"
      scopes: ["openid", "email", "profile"]
    - name: "github"
      client_id: "<GITHUB_CLIENT_ID>"
      client_secret: "<GITHUB_CLIENT_SECRET>"
      scopes: ["user:email"]
    - name: "discord"
      client_id: "<DISCORD_CLIENT_ID>"
      client_secret: "<DISCORD_CLIENT_SECRET>"
      scopes: ["identify", "email"]

cookie:
  name: "csar_session"
  secure: false       # Set to true in production (requires HTTPS)
  same_site: "lax"    # strict | lax | none
```

Sensitive values can be passed via environment variables using `${VAR_NAME}` syntax in the YAML file.

### Running

```bash
# Build and run
make run

# Or build first, then run manually
make build
./bin/csar-authn -config config.yaml
```

## Development

```bash
# Run tests
make test

# Run tests with race detector
make test-race

# Lint (requires golangci-lint)
make lint

# Clean build artifacts and generated keys
make clean
```

## Key Management

On startup, `csar-authn` looks for PEM key files in the following order:

1. Explicit `jwt.private_key_file` and `jwt.public_key_file` paths in config
2. `<key_dir>/private.pem` and `<key_dir>/public.pem`
3. If neither exists and `auto_generate: true`, a new key pair is generated and saved to `key_dir`

Key IDs (`kid`) are derived from the SHA-256 hash of the DER-encoded public key (first 8 bytes as hex), matching the `ComputeKID` convention used by the csar router.

## JWT Claims

Tokens issued by `csar-authn` include the following standard claims:

| Claim | Description |
|-------|-------------|
| `sub` | User UUID |
| `email` | User email address |
| `display_name` | User display name |
| `iss` | Issuer (configured `jwt.issuer`) |
| `aud` | Audience (configured `jwt.audience`) |
| `exp` | Expiration time |
| `iat` | Issued at |
| `nbf` | Not before |

## Project Structure

```
csar-authn/
├── cmd/csar-authn/      # main package — wires dependencies and starts the server
├── internal/
│   ├── config/         # YAML config loading
│   ├── handler/        # HTTP route handlers
│   ├── oauth/          # Goth OAuth provider setup and callback logic
│   ├── session/        # JWT signing, key management, and JWKS serving
│   └── store/
│       ├── store.go    # Store interface
│       └── postgres/   # PostgreSQL implementation with embedded migrations
└── config.example.yaml
```

## OAuth Redirect URIs

Register the following callback URL with each OAuth provider:

```
<base_url>/auth/<provider>/callback
```

For example, with `base_url: "http://localhost:8081"`:
- Google: `http://localhost:8081/auth/google/callback`
- GitHub: `http://localhost:8081/auth/github/callback`
- Discord: `http://localhost:8081/auth/discord/callback`

## License

MIT

## Transactional audit outbox (activation gated)

`audit_outbox_enabled: false` is the default. Enabling requires PostgreSQL and a
configured router-backed `audit` STS transport, and requires a restart. Deploy
compatible core and confirmed-ingest audit images first. Mixed old ingest instances
can acknowledge before durable acceptance; do not enable producers until all are upgraded.

Business writes and outbox entries share one transaction. Failed enqueue rolls back
the mutation. Relays use SKIP LOCKED, service-scoped claims and 60s fenced leases;
a 30s send plus 5s finish fits that lease. A missing/lost receipt retains the original
ID, timestamp and payload for retry. One bounded sender per replica owns its router
transport. Network calls never hold the business transaction. Pending copies are
removed only after confirmed acceptance. Already-issued tokens and business behavior
retain their existing semantics. Outbox schema is created only when the mode is enabled.

Metrics are audit_outbox_pending_events, audit_outbox_oldest_age_seconds and
audit_outbox_scrape_success. Database-query errors omit backlog values and report
scrape failure rather than a false zero. Configure alert delivery separately.

Coverage: service-account create/reactivate, policy update, rotation/revoke; personal
API-key create/revoke. These entries carry safe identifiers/policy projections and
public-key fingerprints, never key PEMs, personal-key hashes or token prefixes.
Other sessions, passkeys, profiles, account merge, legacy sync and billing/campaign
producer classes are not yet transactional. They retain the existing async emission;
only exact covered action names suppress post-commit duplicates. Direct store calls
without a verified handler actor are explicitly marked unattributed.

### Legacy sync and transaction poolers

Legacy sync apply needs `legacy_users_sync.lock_database_dsn` pointing at a
session pool or direct PostgreSQL. In production this is
`CSAR_AUTHN_LOCK_DATABASE_DSN`, using the `csar_authn_session` Odyssey alias,
the existing authn user/password and the same real authn database. This adds
no database or role. The normal DSN remains transaction pooled.

Each attempt opens a dedicated connection and keeps the session advisory lock
across planning and all separate link/create transactions. Closing this client
releases ownership; Odyssey must run DISCARD ALL before reusing its backend.
Acquire and cleanup are bounded to five seconds; cleanup ignores caller
cancellation. Missing DSN fails apply closed, while dry-run is unchanged.
DSN changes require a restart and are rejected by the config watcher.

This fixes backend reassignment by transaction pooling, not failover fencing:
loss of the lock connection/primary does not atomically fence separate writes.
Do not enable a sync job across a planned primary switch. No new claim of
cross-primary exactly-once sync is made.

Run isolated pooler acceptance from the configs repository with
`python3 scripts/test-odyssey-session.py --authn-repo /path/to/csar-authn`.
Use a Go workspace containing the matching csar-core schema revision when
these PRs have not yet been released. No production DSN is accepted by tests.

## Email OTP delivery

Email OTP supports Yandex Cloud Postbox and Selectel Mail Service. Existing
`email_otp.postbox` settings keep selecting Postbox. To select Selectel, remove
that block and configure:

```yaml
email_otp:
  enabled: true
  sender_address: "${EMAIL_OTP_FROM_ADDRESS}"
  sender_name: "AURUMSKYNET ID"
  delivery:
    provider: selectel
    selectel:
      username: "${SELECTEL_SMTP_USERNAME}"
      password: "${SELECTEL_SMTP_PASSWORD}"
      # Defaults: smtp.mail.selcloud.ru, implicit TLS on 1127, 10s timeout.
```

For required STARTTLS, set `tls_mode: starttls`; the default port becomes 1126.
Certificates are verified and plaintext submission is forbidden. The sender
must belong to a domain verified in Selectel. Follow the
[Selectel setup guide](https://docs.selectel.ru/email-service/connect-email-service/)
for verification and SPF/DKIM/DMARC records. Credentials are the mail resource's
SMTP credentials, independent of Yandex's service-account key.

The new `delivery` block also accepts `provider: postbox` with a nested `postbox`
section using the existing schema. Both Postbox forms require an HTTPS endpoint
without URL credentials, query or fragment. Configuring both legacy `postbox`
and new `delivery`, or both provider sections, is rejected.

All enabled Email OTP settings, including TTL, cooldown, rate/attempt limits,
effective transport/credentials, sender address/name and subject, require
restarting authn. Enabling or disabling OTP also requires a restart. The watcher
rejects the entire reload before OAuth, STS or handler changes if any of these
settings differ from startup, keeping the sender, registered routes and OTP
handler consistent. Equivalent legacy and new Postbox syntax is accepted.
Editing a Postbox service-account key file in place also requires a restart:
the watcher compares the configured path, not file contents.

Authn still generates, hashes and verifies codes itself and submits emails
synchronously. Provider acceptance is not proof of inbox delivery. A connection
loss after SMTP DATA may hide an accepted message; authn reports the existing
send-failure response and does not automatically retry or switch providers.
Provider replies and OTP content are excluded from transport errors.

The production Compose stack still mounts the legacy Postbox credential file.
An SMTP-only rollout must update that host wiring as well as the manifest and
image. This source change does not switch or deploy the production provider.
`csar-notify` email remains disabled pending verified contacts and durable
per-target delivery tracking.

## Personal-key scope consent (source only, October 22, 2026)

`POST /auth/me/api-keys` remains cookie-session and trusted-Origin only. Its
request is `{ "seller_id": "<seller UUID>", "label": "<label>", "scopes":
["analytics:read"] }`. Supported selections are `adverts:read` (saved settings),
`analytics:read` (Analytics) and `advertising:read` (Mass Adverts performance),
individually or combined. Omission preserves the legacy `adverts:read` default; explicit null,
empty arrays, duplicates, unknown names and write scopes are rejected. Creation
requires current `campaign_module/massAdvert.read` for adverts/advertising and
`campaign_module/analytics.read` for analytics, each in `wildberries:<seller>`.
If any requested permission is denied or cannot be checked, no key is issued.

Create/list responses expose the issued `scopes` array. Introspection returns
that persisted authority without adding newly available scopes. Scope changes
require a new key and explicit consent; existing keys cannot be upgraded in
place. The five-active-key limit, 90-day expiry, seller binding, hashed storage,
session-only revoke and current permission checks in the router remain intact.
The router's positive introspection cache still applies (15 seconds by default,
or the configured route cache TTL, capped by expiry); revocation is observable
after that existing cache bound. Module permission changes remain governed by
the router's authorization checks and their configured policy/cache behavior.

Migration `021_seller_api_credential_scopes` adds a constrained, non-null text
array. Legacy rows and inserts from older binaries default to only
`adverts:read`. No deployed key gains analytics authority. The migration is
additive and old writers tolerate it; keep the column on application rollback.

Keys containing analytics or advertising consent use `aurum_pat_v2_` followed by the same
32-byte random base64url payload. Existing router prefix checks accept this
format. Older authn introspectors require the original exact token length, so
they return inactive for v2 keys instead of incorrectly granting advert access.
New introspectors accept both formats. This makes mixed-version rollout and
application rollback fail closed, although new keys can be intermittently
rejected until all introspection replicas have upgraded. Enable the UI scope
selector only after authn convergence and Analytics routes are ready. There is
no server-side bypass of explicit scope selection or per-module permission.

Regression tests cover legacy omission, analytics-only and combined consent,
denied permissions, malformed selections, persisted introspection, token
version compatibility, seller binding and unchanged TTL/cap. The PostgreSQL
integration fixture uses only a guarded localhost `csar_audit_test` database
and a unique disposable schema. It verifies pre-migration backfill, repeated
migration, old inserts, constraints, new persistence/listing, owner isolation,
expiry and revocation. No migration or credential issuance was run in production.

Migration `022_seller_api_advertising_scope` expands the constrained vocabulary
to three unique scopes without updating any row or changing the advert-only
default. Earlier scope-aware authn replicas reject the unknown
`advertising:read` value instead of substituting another grant; original
introspectors reject the v2 token length. Thus the v2 format remains sufficient
for fail-closed rollback. Finish upgrading all introspection replicas before
enabling the new scope choice. The Advertising scope also has its own route
policy and cannot be substituted by a saved-settings or Analytics key.

### Retired MCP issuer

The application-specific MCP OAuth/manual/discovery/proof endpoints and static
client catalogue are removed. Configure the generic credential profiles and
`credentials.public_oauth` explicitly. Retired enabling/catalogue environment
settings fail startup; remove them only during a separately approved rollout.
`MCP_OAUTH_REDIS_ADDR` and `MCP_OAUTH_REDIS_PASSWORD` remain connection aliases
with the same pool, fallback, quotas and Redis identities.

Existing personal API keys keep their reader, list/revoke, scopes and fixed
expiry. No key reissue, revocation, historical row rewrite or production activation
is included. Historical MCP rows still count toward the same owner cap and are
cleaned up by caller revocation; their retired protocol cannot be used.

Run generic lifecycle acceptance with `AUDIT_TEST_DATABASE_URL` pointing to the
disposable localhost `csar_audit_test` fixture. Native client/rollout acceptance
remains separate from protocol fixtures.

## Universal credential storage (source only)

Migration 030 adds generic grant, hashed-secret and browser authorization-request
storage. It preserves existing seller credentials, caller bindings and historical
migrations; it does not backfill, dual-write, adopt or reissue old credentials.
No generic HTTP issuance or bearer format is enabled by this preparation.

The immutable grant owns consent, profile/revision, exact audience, namespaces,
owner/caller and original deadline. Code/refresh redemption cannot extend that
deadline; derived proofs also cannot outlive their presented source. Refresh
rotation rejects old access values; spent-refresh reuse revokes the whole parent
with durable audit, including reuse after the spent value's individual expiry.
One-use proof, refresh, create and revoke changes roll back on audit failure.
Caller-wide revoke covers both representations; account merge revokes new grants
without transferring consent. Readers require a live unmerged owner and caller.
Physical deletion of owners/callers with retained new history is denied.

API-key and connection caps count both families under the existing owner lock.
All writers/readers must converge before new issuance; rolling back a writer
requires disabling unsupported issuance first. Preserve additive state and audit
on rollback. No automatic secret-history purge is installed. Public issuer/client
admission, current Authz checks and migration of consumers follow separately.

Run the real PostgreSQL fixtures only against a disposable localhost
`csar_audit_test` database, using `AUDIT_TEST_DATABASE_URL`; optional legacy tests
also use `CSAR_TEST_DSN`. The Go quality workflow provisions this fixture itself.
Local acceptance: `go build ./...`, `go test ./... -count=1`,
`golangci-lint run ./...`, and
`go test -race ./internal/store/... ./internal/handler -count=1`, with those
fixture variables set. Odyssey pooler acceptance is separate and remains required
before any operational rollout. No production migration or deployment is included.


## Generic credential receiver (opt-in)

`credentials.enabled` is absent/false by default. Enabling the source capability
requires secure owner cookies, verified mTLS, the existing transactional audit
outbox, configured per-feature dedicated CA/peer and a bounded `decisions` STS
RouterClient. Deploy compatible v2 routers/coordinators/helpers before issuance;
`csar.delegation_contract_version=2` preserves required route fields. This source
change does not activate deployed configuration or migrate old credentials.

Profiles can explicitly declare `accepted_grant_revisions: [1, 2]` alongside
`revision: 2`. Omission accepts only the current revision. Lists contain 1–32
unique positive revisions, include the current revision and exclude future ones.
Acceptance is the profile owner's reviewed semantic-compatibility declaration.
Every inspection/refresh/proof use intersects immutable consent with current
scopes/namespaces/selection policy. Resource evaluation and proof use also require
current Authz decisions; inspection remains consent metadata only. Expansion cannot
widen existing consent. No stored revision or original deadline is relabeled.
Profiles, compatible revisions, decisions, trust, cookie and TLS settings require
restart, rejected before partial reload changes.

Owner-session routes create/list generic personal API keys at
`/auth/me/credentials`; GET/DELETE `/{grant_id}` provide details and revoke.
Direct issuance defaults to the API-key family and its five-key aggregate cap.
An explicit profile `manual_issuance: {family: connection, max_ttl: 168h}` selects
the shared 100-connection accounting family with no client/code/refresh authority.
Its maximum must fit the parent grant TTL and 1–168h; `ttl_seconds` may only
shorten it (minimum 1h for connections). Explicit API-key maxima are positive
whole seconds within grant TTL. Body `kind` is only a compatibility assertion,
never the family selector. Omission preserves existing API-key lifetime behavior. Browser JSON authorization/consent and
form-encoded code/refresh redemption live under `/oauth/credentials`. Existing
bounded public-client registration rows are consumed through an owner adapter.
These are generic issuer APIs; public OAuth metadata/DCR/CIMD and application UI
wire adapters are migrated separately. Current legacy APIs remain available.

The dedicated v2 introspection endpoint is
`POST /internal/credentials/v2/introspect`. Private
`POST /svc/credentials/inspect` returns bounded consent metadata, never a current
permission result. `POST /svc/credentials/evaluate` checks at most 100 exact refs
using configured Authz decision profiles through CSAR/STS, with complete correlated
results or an unavailable error. Optional resource-proof issuance is restricted
to one allowed ref and the verified original grant/caller/deadline. Inspection
and evaluation each require an explicit service capability and pinned ingress.
Proof binding is part of the complete hashed opaque token, not a caller assertion.

Manual tokens are fixed-lifetime and nonrenewable; OAuth refresh cannot extend
the original grant deadline or add current configuration authority. Public token
exchange authenticates its own audit caller and never adopts incoming origin
assertions. New endpoints remain disabled until configured. No production DDL,
Redis changes, signing-key changes or deployment is included. Retain the outbound
Telegram-ID JWT bridge and stage obsolete incoming-path retirement only after
consumer migration and inventory.

Email OTP uses generic sign-in wording by default. Optional `email_otp.display_name`
adds a bounded single-line product name to the body (escaped in HTML), independently
of `sender_name`. An explicitly configured `subject` remains exact. Configure
application branding as data during a separately approved rollout.
