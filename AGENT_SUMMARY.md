# csar-authn Agent Summary

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
- Bot verification and account merge flows.
- Optional admin permissions and service-account management.

## Dependencies
- PostgreSQL for identity/session state.
- OAuth providers configured in YAML and env-backed secrets.
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
