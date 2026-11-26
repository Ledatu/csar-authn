## Bounded owner consent metadata — source only

GET /auth/me/credentials?view=consent returns five complete non-secret original
consent snapshots per page, optional exact kind/profile filters and explicit
consent-only semantics. Caller labels/kinds come from the owner registry. Owner
capacity hints reuse the exact mutation-path SQL and mixed legacy/generic totals;
ceilings and owner-locked admission remain unchanged. Default summary is preserved.
Unknown/duplicate filters and oversized pages fail closed. Request-info includes
configured access/grant bounds so the seller UI can show the deadline it requests.
This supplies the direct generic UI migration, without a new legacy MCP adapter,
per-grant HTTP fan-out, DDL, Redis or deployment change.

## Generic public OAuth receiver — source only

Optional credentials.public_oauth enables standard metadata/GET authorization,
DCR/CIMD client admission and terminal browser-bound denial over the existing
generic issuer. Exact configured profiles/resources/aliases and current profile
revision bind every browser transaction. Public client names are immutable
self-declared display snapshots in version2 client_binding JSON; no DDL or old
row rewrite. Codes, refresh, original callback, PKCE, consent and owner/caller
caps reuse existing transactions and durable audit. Owner shortening bounds code
and access deadlines as well as the grant. Denial consumes the pending request
atomically with outbox and cannot later approve. Profile/scope substitution fails
before resource decisions; request IDs use a valid req_ prefix with fresh entropy.

The one public_oauth_clients.go implementation consolidates existing admission,
public-HTTPS/SSRF metadata fetch, slots/singleflight/locks and storage. Protected
Redis prefix/policies, caps and retention remain unchanged, shared across aliases.
No new legacy MCP adapter layer. Existing old endpoints remain only until direct
UI migration/replacement acceptance; the outbound Telegram-ID JWT bridge is kept.
A compatible Core public receiver loader is required. Production/Redis/deployment
settings are unchanged; no public activation is implied by merge.

## Account-bound private operations and direct access (approved §21, source only)

Generic private inspect/evaluate require the verified account profile/original revision/audience plus owner/caller/grant/service/trust checks. Direct access-resource introspection accepts only an access secret, narrows original consent and checks current Authz before the audited use transaction. The dedicated UseCredentialAccess store operation locks current owner/caller/grant/secret, enforces immutable consent, audits use and creates/consumes no secret. No DDL or signing-key changes. Production, Redis, deployment and outbound Telegram-ID JWT behavior are unchanged.

## Universal credential issuer and management (U05b/U07, opt-in)

Core #48 supplies explicit compatible grant revisions and pure current-policy
narrowing. Authn's receiver loader permits enabled credentials only with secure
session cookies, verified TLS and transactional audit; startup also requires the
live generic PG/outbox/client stores, bounded routed STS decision client and every
configured dedicated CA/peer. All policy, cookie and TLS changes require restart.
The existing router v2 capability/receiver gates were merged first (router #63).
No deployed setting or route is enabled by these source changes.

Generic owner routes `/auth/me/credentials` create/list keys, with GET/DELETE
`/{grant_id}` for bounded non-secret detail and revocation. Creation requires the
real owner's direct cookie session and exact configured Origin; impersonation,
service bearer substitution and arbitrary family labels deny. Manual issuance defaults to
API keys. Explicit profile `manual_issuance` can select the connection accounting
family and a fixed maximum (1–168h), sharing the existing old+new 100-connection
cap. The optional `ttl_seconds` only shortens it; body kind cannot select a family.
No client/code/refresh authority is created. OAuth-family
creation uses the browser/client/PKCE flow under `/oauth/credentials/{authorize,
requests/{id},approve,token}`. The new browser API is JSON and returns an exact
callback for the application adapter; public OAuth/DCR/CIMD representation and
consumer migration remain U12 work. Existing stored public clients are reused;
new anonymous metadata/registration admission is not implicitly activated.

Dedicated `/internal/credentials/v2/introspect` enforces exact profile/namespace/
audience/scope/purpose/resource and typed caller metadata. The complete opaque
proof, including bounded public scope/namespace binding, is hashed; modifying
that binding cannot resolve its immutable row. `/svc/credentials/{inspect,
evaluate}` additionally require the configured service/operation/profile, its
own CA/peer and live verified original owner/caller/grant context. Inspection is
consent metadata only. Evaluation intersects consent/current policy with live
Authz U03 results and may issue one resource proof in its outbox transaction.
Authz is reached through Core RouterClient/STS, never a copied permission engine.

All issue/refresh/use gates retain the original consent revision/deadline and
intersect current policy; unlisted revisions/removed profiles deny. Refresh
rotates atomically and spent-token reuse revokes the family. Public credential
exchange replaces asserted gateway audit identity with its actual verified
credential; trusted service calls preserve their separately verified hop/origin.
Anonymous request admission is bounded to 32 pending/client and 4096 retained
requests, with a 2s transaction and at most 100 expired browser rows cleaned per
start. Approval takes write intent before the request row to avoid cleanup lock
upgrade deadlocks. No credential, refresh-replay or audit history is purged.
Registered handlers have 10s operation contexts; body/selectors/batches are bounded.

Local PostgreSQL lifecycle, revision, two-application, scope/namespace, current
Authz, session/origin/TLS, audit rollback, capacity and expiry-race coverage is
required. All old issuer/consumer paths remain until verified migration. Outbound
Telegram-ID JWT signing, Redis, production DDL/config and deployment are unchanged.

# csar-authn Agent Summary

## Universal credential storage (U06, source only)

Migration 030 appends `credential_grants`, `credential_secrets` and
`credential_authorization_requests`; legacy tables/rows/migrations stay intact.
The grant is the sole immutable owner/caller/consent/original-deadline authority,
with a direct same-owner caller FK and no duplicate legacy binding. New optional
`GenericCredentialStore` uses Core constraints and strict versioned decoding,
including exact uint64 revisions and opaque cross-namespace resource IDs. Only
SHA-256 hashes enter the secret table; no token/hash/browser state enters audit.

All credential mutations require the existing transactional audit outbox.
Creation/approval, one-use proof exchange, refresh rotation/replay-family revoke,
single/caller-wide revoke and source-owner merge revocation commit atomically
with audit. Lock order is owner, caller, grant, secret. Access rotation retires
old access values; spent refresh evidence remains through the parent lifetime
and is not purged automatically. Code/refresh redemption is bounded by original
consent deadline; proofs are also bounded by presented source expiry. Readers
require the grant, caller and unmerged owner to remain live. Account merge never
transfers new consent, including rollback to a writer that only soft-merges.
Physical owner/caller deletion with retained generic history is denied by FKs.

The existing owner-serialized API-key/connection caps now count old and new
families. Generic issuance must wait for all relevant writers/readers to converge.
The U05b/U07 issuer above supplies direct-session/CSRF/impersonation guards,
exact profile narrowing, deterministic format/purpose dispatch and current Authz
checks. Public registration/metadata adapters remain consumer migration work.
It changes no runtime enablement, Redis, production DDL/config, certificates or
outbound Telegram-ID JWT behavior. Local disposable PostgreSQL lifecycle,
concurrency, audit rollback and legacy migration compatibility tests cover U06;
the existing Go quality workflow now supplies localhost PG for these fixtures.

## Feature-specific ingress trust (U05a, source only)

`origin_router_peer_cn` explicitly pins the origin issuer's verified peer name
beside its dedicated CA. The explicit registration path has no application
default; existing origin/MCP wrappers retain their old compatibility peer.
CA/pool transport registration admits only configured peers, while each issuer
checks its own immutable CA+peer pair per request. Sharing a CA with another
feature never imports that feature's peer authorization. Dedicated roots are
isolated from general personal-key introspection: that compatibility receiver
requires an actually verified general-service chain and excludes dedicated issuer
roots even when the leaf uses the same `csar-client` CN. Peer/profile changes
are restart-only and rejected before reload mutation. Existing dedicated/general
CA separation and pool-specific registration checks remain. This pins merged
Core trust configuration but changes no certificate, key, token contract, Redis
or deployment. Outbound Telegram-ID route-token signing is unchanged. Generic
credential issuance is opt-in through U07 above; deployed enablement is unchanged.

Dynamic onboarding also exposes owner-session `POST /oauth/mcp/tokens` for
clients that support Bearer headers but cannot perform OAuth. It issues only
hashed, MCP-resource credentials, with no OAuth client, code or refresh token,
an explicit1–168h deadline, selected/all-store consent and an atomic caller
binding/audit. API PATs remain a separate audience. Both issuance paths serialize
the100-live-connection owner cap; changing clients cannot reset it. Consent and
revoke reuse the API-key trusted seller/dev-origin guard. Connection last-use is
approximate to one write/hour; delegation updates it before shared grant locking.
Migration029 adds only nullable last_used_at. Bound connection revocation requires
the transactional outbox and deletes outstanding proofs/refresh rows atomically.
The feature remains disabled unless dynamic onboarding is enabled; no rollout.

New owner-issued API keys and MCP approvals create their caller in the same
credential/binding/audit transaction unless the owner reuses an existing caller.
`caller_kind: agent` is an explicit owner choice; omission registers a generic
application and never infers an agent from product names or transport. The owner
cap is20 active callers; reuse requires the same owner and an active immutable
registration. Failed binding/audit rolls back creation. Existing unbound tokens
remain unknown. MCP connection lists expose the bound caller and self-declared
client name separately, preserving legacy single-store selection semantics.

The manifest can explicitly set `origin_router_ca_file` to the existing dedicated
router CA. The existing ORIGIN_ROUTER_CA_FILE override keeps precedence; absent
settings remain disabled. Registration retains exact dedicated CA/CN verification
and may reuse the already mounted MCP public CA. Both issuer trust and audit
outbox are restart-only: config reload rejects changes before applying any fields.

Audit producers explicitly use Core's trusted-context enrichment before enqueue
or async emission. Successful own-session/JWT authentication replaces any incoming
gateway caller/origin context; cookie sessions identify their human owner/effective
subject without exposing cookie IDs, while old JWTs keep absent metadata. Account
merge resolution updates only the effective subject of an already verified claim.
Transactional caller registration/binding and key/service-account mutations retain
caller/operation/trace alongside legacy Actor. This does not activate outbox,
registry routes, delegation or production migrations. Runtime uses Alpine3.24.4
with upgraded CA/zlib; existing signing material and cookie/OAuth contracts remain.

Origin attribution issuance is opt-in via ORIGIN_ROUTER_CA_FILE. Startup requires
verified mTLS with the dedicated router CA and aurum-api-router-client leaf CN;
general service trust cannot assert root callers. Existing MCP and origin issuer
features reuse the same dedicated ingress registration. Root receives only a
gateway-verified principal and source deadline. Delegation additionally requires
gateway-confirmed service/STS metadata and a parent addressed to that service.
All JWT access verifiers must reject reserved origin purpose before activation.
No production route/CA/env rollout is included; root-client wiring and confirmed
audit release remain separate acceptance gates.

W2 session validation returns caller metadata on both the existing header-only
GET and JSON POST contracts, plus the validated session deadline. Responses are
no-store; raw session cookie values are never credential references. CSAR must
adopt the matching contract before expiry-bounded caller forwarding is active.

New signed session/STS JWTs include versioned caller metadata. Session JWTs
identify their user principal; reusable STS JWTs contain only the service hop,
without per-user/origin context. Old tokens retain absent metadata and existing
expiry. Cookie bearer IDs and token hashes are not used as credential references.
Gateway verification/forwarding and signed origin delegation remain W2 work.
Historical service names outside the bounded caller-reference syntax retain
their existing STS subject/issuance with absent optional metadata.

MCP consent optionally binds an owner caller in the grant/audit transaction.
Introspection preserves that caller across access refresh and one-use proofs,
with separate client/connection metadata. Unbound grants remain unknown; the
MCP transport/client name does not classify a caller. No callback/grant expansion
or route configuration is included. Local MCP lifecycle tests cover both modes.

Owner-session caller handlers register/list/revoke identities with the existing
credential origin/impersonation guard. API-key creation accepts optional caller_id;
introspection resolves authoritative binding, preserves legacy unknown and fails
closed on revoked/inconsistent lookup. Session POST validation distinguishes
human owner from effective impersonated subject; raw session IDs are not exposed.
CSAR header adoption/public route configuration remain W2/deployment work.

Migration 027 adds immutable generic credential-to-caller bindings. New API keys
can bind in the same audited transaction; legacy rows are not backfilled. Caller
revocation atomically invalidates bound API keys and MCP grants/connections.
Lookup distinguishes missing legacy binding from revoked/mismatched registration;
do not downgrade the latter to unknown. HTTP/token response adoption follows.

## W1 caller registry storage (source only)

Migration 026 adds owner-scoped agent/application registrations with immutable
kind/owner and stable IDs independent of credentials. Creation/revocation require
the existing transactional audit outbox; no async fallback. Listing is explicitly
active-only and bounded. HTTP registration and token bindings follow separately;
human/service principals retain their existing issuer stores. No production DDL.

## Hosted seller OAuth

The optional seller MCP issuer uses authorization codes with PKCE S256 and
browser-bound consent. `MCP_OAUTH_ENABLED` controls issuer startup independently
of static registrations; omission preserves legacy enablement. Explicitly opting
into `MCP_OAUTH_DYNAMIC_CLIENTS=true` enables CIMD discovery and bounded DCR,
requiring PostgreSQL client storage, Redis and public-only HTTPS transport.
Delegation retains the dedicated router CA and exact peer identity. Credential
management requires the owner's direct session; revocation closes grant/proofs.


## Role In Prod
`csar-authn` is the authentication service for the CSAR stack. In prod it handles OAuth login, issues session JWTs, serves JWKS for the router, and exposes STS and admin-style authn endpoints that other services reach through the router or via the configured authz client.

## Runtime Entry Points
- `cmd/csar-authn/main.go` wires config, storage, observability, OAuth, STS, authz, and HTTP serving.
- `internal/handler/handler.go` defines the HTTP surface.
- `internal/session/*` owns JWT signing keys and JWKS serving.
- `internal/sts/*` implements token exchange and replay protection.

## Trust And Auth Model
- The router validates end-user sessions and injects `X-Gateway-*` headers before backend handlers read them through `gatewayctx`.
- `csar-authn` issues its own JWTs and publishes the public key set at `/.well-known/jwks.json`.
- Optional authz integration is used for permissions/admin flows, and audit events are sent through the router-backed audit client when configured.

## Critical Flows
- OAuth login and callback handling.
- Session issuance, refresh, logout, and JWKS publication.
- STS token exchange and replay protection.
- Database service accounts retain their name after revocation. Admin creation
  reactivates a revoked name only with a fresh public key, replaces its audience
  policy and TTL, and increments its generation. Active database policies can
  be replaced through `PUT /admin/service-accounts/{name}/policy` with an
  `If-Match` revision. The list supports `status=active|revoked|all`; config
  accounts appear as read-only effective entries and win name collisions.
- STS reads the current database row on every exchange. A committed revoke,
  reactivation, key rotation, or policy edit affects subsequent exchanges on
  every replica; a database read error fails closed for database accounts.
  Already-issued tokens remain valid through their expiry.
- Seller personal API keys: cookie-session creation/list/revocation, hashed
  storage with a five-active-key cap and 90-day expiry, per-requested-scope
  current module permissions at creation, and mTLS-only introspection for the
  router. `POST /auth/me/api-keys` accepts optional `scopes`: `adverts:read`
  `analytics:read` and/or `advertising:read`; omission preserves advert-only consent. Empty/null,
  duplicate and unsupported selections fail. Migration 021 backfills legacy
  rows/defaults to advert-only; introspection returns stored scopes unchanged.
  Migration 022 adds only the Advertising consent vocabulary; existing rows
  and defaults are unchanged. Advertising requires current `massAdvert.read`.
  Analytics- or Advertising-containing keys use `aurum_pat_v2_` so legacy introspectors reject
  their different length instead of assigning hardcoded advert access. Mixed
  replicas can reject new keys until upgrade convergence; rollback fails closed.
  Earlier scope-aware replicas reject unknown Advertising consent, preserving
  fail-closed rollback. Source only: no keys issued or production migration applied.
- Bot verification and account merge flows.
- Optional admin permissions and service-account management.
- `POST /svc/authn/users/resolve-links` maps Telegram/Yandex provider ids to authn user ids (mapping only, no profile data, service callers only) for the legacy identity sync.
- `POST /svc/authn/legacy-users-sync?dry_run=true` (`internal/legacysync`) plans the legacy Mongo users into authn users and Telegram/Yandex links: noop, create, link, split_identity, overridden, blocked (email/phone already on another user, provider already linked, August synthetic Telegram rows) or no_identity. Dry run only; Mongo email and phone are compared, never stored; the report carries no profile data. Gated by `legacy_users_sync` (csar-core authnconfig: `allowed_subjects`, `max_users`, `identity_overrides`) and the router policy `authn-svc-legacy-sync`. Plan: `plans/2026-09-26-legacy-sync-apply-mode.md`.

## Dependencies
- PostgreSQL for identity/session state.
- OAuth providers configured in YAML and env-backed secrets. Explicit
  `oauth.enabled: false` skips provider registration/discovery and returns 404
  for OAuth login/callback flows; omission preserves enabled behavior.
  STS and database readiness remain independent of OAuth provider enablement.
- Router-backed authz and audit clients when enabled.
- STS replay storage via Redis or Postgres depending on config.

## Config And Secrets
- Sensitive values include OAuth client secrets, `oauth.session_secret`, JWT private/public keys, authz endpoint/TLS, audit router URL, and STS bootstrap accounts.
- Prod config is manifest-driven via `csar-configs/prod/csar-authn/config.yaml`.
- Key files and cookie/session settings are startup-critical; partial reload does not refresh every outbound client or route.

## Audit Hotspots
- Config reload is partial: OAuth, STS accounts, and handler config refresh, but outbound authz/audit wiring and feature enablement do not fully rebind.
- Admin user search is coupled to the role-assignment permission model, which is a least-privilege smell.
- The authz client and audit client are created once at startup, so config changes to their endpoints or TLS settings need a restart.

## First Files To Read
- `cmd/csar-authn/main.go`
- `internal/handler/handler.go`
- `internal/handler/auth.go`
- `internal/sts/sts.go`
- `internal/handler/service_accounts.go`
- `internal/handler/permissions.go`
- `README.md`
- `config.example.yaml`

## DRY / Extraction Candidates
- Repeated authz/audit client wiring should stay in `csar-core` if it ever becomes shared across more services.
- JWKS and JWT handling should remain aligned with `csar-core/jwtx` conventions rather than diverging further.

## Required Quality Gates
- `go build ./...`
- `go test ./... -count=1`
- `make lint`

## Transactional audit coverage (activation pending, October 8)
- Startup-only `audit_outbox_enabled: false` is the default. Enabling requires
  PostgreSQL and configured router audit transport; the shared outbox migration
  and relay start before serving. Source changes are not deployed.
- Covered mutations: service-account create/reactivate/policy update/key rotate/
  revoke and personal API-key create/revoke. Events commit in the same business
  transaction. Covered handlers suppress their duplicate async emission only
  when the PostgreSQL store advertises transactional coverage.
- Events carry trusted caller/request identity, safe policy fields and a SHA256
  fingerprint of public-key PEM. Private keys, public-key PEM, API-key hashes
  and token prefixes are excluded. CreateServiceAccount remains insert-only;
  the explicit create/reactivate path retains its separate semantics.
- Sessions, passkeys, profile, merge and other mutation classes retain existing
  async audit behavior. This flag does not make all authn activity transactional.
- Enqueue failures roll back mutations; router outages retain the outbox. Core
  backlog metrics distinguish observation failure from an empty backlog.
- Read `internal/store/postgres/audit.go`, `audit_integration_test.go`, and the
  README activation gates. Tests require the guarded local `csar_audit_test` DB.

## Legacy sync session endpoint
Legacy sync apply uses a separate short-lived connection configured by
`legacy_users_sync.lock_database_dsn`. Production maps it to the authn session
alias; no fallback to the normal transaction pool is permitted. Acquire/close
are bounded to5s, close survives request cancellation, and DSN changes require
a restart. Session poolers must DISCARD ALL on disconnect. This preserves the
lock across separate business transactions, but is not failover fencing.

## Email OTP transport selection (source only, October 11, 2026)
- `emailotp.NewSender` renders the existing OTP template through `csar-core/email`.
  Legacy `email_otp.postbox` remains supported. `email_otp.delivery` can select
  `postbox` or `selectel`; Selectel needs SMTP username/password and a verified
  sender domain, with TLS on port 1127 or required STARTTLS on port 1126. Password uses secret.Secret.
- Sending stays synchronous in authn, with existing challenge TTL, rate limits
  and failure behavior. Transport acceptance is not final mailbox delivery.
  Unknown acceptance never triggers automatic failover. Codes do not enter notify.
- `internal/config.ValidateReload` rejects email enablement, effective transport,
  credential, sender, subject and OTP policy changes against startup before
  OAuth/STS/handler reload side effects. The OTP handler captures its config once;
  all its enabled settings require restart. Equivalent legacy/new Postbox syntax
  is allowed. Key-file content changes require restart as well.
  The existing session-lock DSN restart guard remains in the same preflight.
- Transport changes require restart. Production Compose credential mounts need
  separate rollout preparation; current production provider remains unchanged.

## User Avatar Contract — 17 November 2026

Avatar upload/set/delete routes, S3 signing/cache/client, provider/legacy photo persistence and avatar profile/directory fields are retired. Identity SQL does not reference avatar columns. Historical migrations remain immutable; physical column retirement is an explicit post-rollout operation, never an automatic rolling-start migration.

## Bot confirmation retries
- ConfirmBotVerification accepts a repeat only for the same provider and
  provider ID while the original code is unexpired. Confirmed and consumed
  states keep their original timestamps and cannot be consumed twice.

## Account-wide MCP grants

Account MCP grants store an explicit campaign selection or all current and future eligible Wildberries campaigns. Migration 024 preserves existing single-cabinet grants. An empty candidate page returns whether the subject has a direct platform administrator assignment. The Campaigns-only access filter checks the authenticated owner and current analytics permission. A discovery credential is single-use. Resolving a live campaign can issue a second single-use credential bound to that seller for the v2 report.

The private `POST /internal/seller-mcp/v1/introspect` endpoint implements
the shared authntokens delegation contract for the seller MCP audience. It uses
the same dedicated router certificate check, grant store and single-use proof
consumption as the original seller endpoints. Campaigns owns resource discovery.
The adapter supplies the canonical Wildberries tenant for resource use.

Seven-day seller MCP consent is explicit in the browser approval. The token
endpoint issues hourly access and rotating refresh credentials for these grants.
Only credential hashes enter PostgreSQL. Reusing a spent refresh revokes the
connection. Existing one-hour approvals keep their original deadline. Deploy
the migrated issuer on all replicas before enabling the updated consent UI.

## Separate MCP public clients

MCP_OAUTH_CLIENTS is a bounded JSON array of client_id, redirect_uris and optional
allow_loopback_port. It adds explicit registrations beside the primary pair;
duplicate IDs, unknown fields, wildcard/invalid callbacks and invalid loopback
policies fail startup. This is a legacy compatibility path; no client secret exists.
VS Code may vary only the numeric port of a registered HTTP loopback-IP callback;
HTTPS, DNS localhost, host and escaped path remain exact. Every code/refresh
remains bound to the actual client; authorization stores the exact requested
callback and token redemption must present that identical value. Consent first
looks up the callback by browser+request+client, then atomically consumes the same
exact binding. Dynamic consent uses the validated snapshot rather than re-fetching
mutable metadata. Refresh/code exchange use the original stored grant binding
and survive removal of the static catalogue. Unexpected client authentication
is rejected; all supported clients currently use the public `none` method.

The platform-admin beta check remains in gateway policy; registration alone
confers no data access. Existing grants retain their client IDs and deadlines.
## Dynamic MCP storage preparation

Migration028 adds bounded immutable public-client registrations and browser-bound
client-name/refresh-policy snapshots. Registration deduplicates canonical metadata
under a replica-wide transaction cap; unapproved leases expire after24h, pending
authorization protects them, and approved clients are retained. Consent persists
the callback and policy selected when authorization began. Existing requests
default to refresh-capable; old replicas remain compatible with additive columns.
Dynamic mode publishes `/oauth/mcp/register` and browser-bound request details.
Metadata uses safe Core HTTP retrieval, a64KiB cap,3s timeout, eight local fetch
slots, Redis coalescing/cache and shared anonymous quotas. HTTP cache directives,
Age and Date determine freshness up to10min; failed/malformed documents are not
cached. Redis uncertainty denies new metadata work instead of amplifying fetches.
Names remain self-declared. Only explicitly offered public authentication and
intersecting code/refresh grants are selected; key-only clients are rejected.
HTTP loopback IP ports may vary; native-declared localhost ports may also vary.
The exact callback path/query remains bound, including at code redemption.
Existing grants retain their consent-time policy and fixed deadline; remote
metadata failure blocks new authorization without redefining an issued grant.
The feature remains opt-in; no deployment or production flags change here.

## MCP Redis isolation

Dynamic MCP startup accepts MCP_OAUTH_REDIS_ADDR and MCP_OAUTH_REDIS_PASSWORD
for its existing bounded pool/cache/admission store (DB0). When absent, the
existing generic redis configuration remains a compatibility fallback. A
password without its dedicated address fails closed. The dedicated settings
never populate or change generic Config.Redis: PostgreSQL-backed STS replay
protection stays PostgreSQL-backed. Production can reuse redis:6379 HAProxy and
the existing cluster password without changing Redis servers, limits or keys.

## MCP discovery candidate selection

The existing Campaigns-only eligibility roster probe includes optional `selection`
only when `?selection=v1` is requested with a live owner-bound grant. Verified router mTLS and the pinned
Campaigns service principal remain mandatory. Selection is consent metadata only,
never proof of current tenant/lifecycle/analytics access. Old consumers retain the small original response;
new consumers may narrow candidate queries before pagination, then check live
eligibility normally. Browser probes have no selection. No route, token, migration
or deployment changes accompany this additive response.

## Generic OTP branding (source only, November 26)
- Email OTP defaults to a generic subject/body. Optional `email_otp.display_name`
  selects the product name separately from the sender header; HTML escapes both
  name and code. Configured subject stays exact. Production branding/config and
  transport behavior are unchanged by source preparation.
