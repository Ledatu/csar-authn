# csar-authn

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
