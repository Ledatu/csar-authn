# Profile-bound public OAuth

This is source preparation. No production endpoint, Redis setting or deployment
is enabled by merging the receiver.

`credentials.public_oauth` declares version1, explicit enablement, public
`authorization_endpoint`/`token_endpoint`, `dynamic_clients` and its
`registration_endpoint`, and a bounded list of `{profile_id, resource_aliases}`.
Profiles and every resource/alias must be unambiguous. Public URLs are deployment
data; generic code contains no application URL, scope or namespace default.
Older config readers reject activation. Authn and helper use the matching Core
public receiver after it is implemented.

The source endpoints are:

- `GET /oauth/credentials/metadata`: issuer-wide standard discovery metadata;
- `GET /oauth/credentials/authorize`: standard code/S256/resource authorization;
- `POST /oauth/credentials/register`: public registration when dynamic admission
  is explicitly enabled;
- existing `POST /oauth/credentials/authorize`: the bounded browser JSON adapter;
- existing `GET /oauth/credentials/requests/{request_id}` and
  `POST /oauth/credentials/approve` for owner consent;
- `POST /oauth/credentials/deny` for terminal browser-bound rejection;
- existing `POST /oauth/credentials/token` for code/refresh exchange.

Public routes require the configured dedicated feature ingress. Anonymous client
metadata is self-declared and proves no software identity or data authority.
Registration/fetch/admission reuse the existing public-client implementation,
stored client IDs, callback rules, SSRF-safe HTTPS client, time/body/slot bounds,
singleflight and owner-safe fetch locks. Protected Redis prefix `authn:mcp:` and
existing policy identities/limits remain shared across aliases and profiles;
configuration cannot rename them or multiply their quotas. The previous Redis
connection options remain in use. No second credential issuer or store exists.

Standard authorization resolves an exact profile/resource, then snapshots client,
redirect, PKCE, requested scopes/namespaces and self-declared name in the existing
five-minute browser request. Version2 `client_binding` JSON carries the name and
original resource alias; version1 rows keep their original representation. No DDL
or stored-row rewrite is required. Consent redirects contain only the request ID;
the secure HttpOnly cookie binds the browser. Owner approval may narrow requested
consent and shorten the configured lifetime. Codes/access/refresh cannot outlive
the grant. Current resource checks and existing owner/caller caps still apply.

Denial consumes the same pending request transactionally with audit. Audit failure
rolls back consumption; a successful denial cannot later approve. Both outcomes
redirect only to the stored callback with the original state and issuer. Raw
secrets, browser cookies and PKCE material are never audit event payloads.

The seller UI migrates directly to this generic flow. No new legacy MCP adapter
layer is introduced. Old application-specific endpoints are retained only until
replacement acceptance and retirement, separately from the outbound Telegram-ID
JWT bridge, which must remain. New public activation and rollout require their
own operational approval after source compatibility and local acceptance.
