# Explicit directory and identity import policy

This source preparation does not enable any deployed feature. The ID portal and
email OTP remain separate from these service/browser directory operations.

## Directory

Without browser_directory, POST /auth/users/resolve and /lookup allow only
`subject` (canonical Authn UUIDs). UUID lookup does not return linked account IDs.
Responses retain minimal id/provider/requested-id/display-name metadata and no
contact or other linked accounts. Exact-ID and batch bounds remain; no fuzzy search.
External provider and linked projection visibility are independent of login config.

Example application-owned policy for existing Aurum member callers:

```yaml
browser_directory:
  version: 1
  providers:
    telegram: {id_format: numeric, username_metadata_key: legacy_username}
  aliases: {aurum: subject}
  projections: {legacy-member: telegram}
```

Canonical callers send `{identifier: UUID, provider: subject}`. A legacy member
adapter explicitly sends `projection: legacy-member`; a numeric Telegram lookup
explicitly chooses provider telegram. Unknown/disallowed projections deny. The UI
never submits subject UUIDs as Telegram member IDs. Alias names are data, not code.

## Import

POST /svc/authn/identity-import is disabled by default, requires verified general
client TLS and the configured exact router peer, and binds router-asserted service
identity to the named importer and source. The router route must validate the STS
service token and strip spoofable identity headers. Login provider enablement does
not authorize asserting imported identities. The request is strict JSON up to1MiB,
with at most the configured records,16 identities/guards per record and bounded
source keys/metadata. Server operation deadline is60s. No bare browser access.

```yaml
identity_import:
  version: 1
  enabled: false
  router_peer_cn: csar-client
  lock_database_dsn: ${CSAR_AUTHN_LOCK_DATABASE_DSN}
  importers:
    aurum-legacy-users:
      subject: svc:legacy-identity-sync
      source: aurum-mongo-users
      providers: [telegram, yandex]
      max_users: 100
      apply: {enabled: false, actions: [], max_links: 0, max_creates: 0}
      overrides: {} # Explicit opaque source-key -> canonical user UUID mappings.
```

Enabled import requires PostgreSQL, verified client TLS and transactional audit.
Apply is additionally opt-in with configured actions/whole-action entry caps and
an explicitly session-safe lock DSN. Directory/import/TLS/audit policy changes
require restart. Runtime and helper use Core's matching identity-policy loader;
older loaders reject declarations.

Request fields: version1, importer, exact source, generated_at and records. Each
record has key, identities[{provider,provider_user_id,optional metadata}], optional
display_name and collision-only email/phone. There is no caller-supplied target
UUID or verified-contact flag. Configured overrides are validated and reported;
they never silently merge or write missing links. Conflict identities are checked,
never asserted. A blocked source record can only remove authority.

No dry_run parameter means dry run. Apply requires `dry_run=false&actions=create`
(or explicitly allowed link). Dry-run responses are metadata only; they grant no
account access. Whole-action over-cap writes none of that action. Apply replans
freshly under the same protected legacy/new session lock. Every entry rechecks
ownership, target and contact absence while briefly locking users/oauth_accounts
against concurrent writes (2s lock wait,5s transaction context). Mutation plus audit
commit together. There is no new table, counter, ownership lease or Redis path.

Email/phone only block conflicts: they are never stored, verified or used as a
linking authority. Split ownership, same-provider ambiguity, stale merged targets,
missing overrides and source conflict guards block. Imported links contain no
provider tokens or verified email state. On an uncertain/partial apply response,
replan before proceeding; do not automatically replay the POST. Per-entry atomicity
does not make an entire batch atomic. Audit stores actor/source/key/provider names,
not contact fields, provider-user IDs or display metadata.

The Wildberries mapper owns usertelegrams, synthetic Telegram guards and duplicate
source identity classification before batching. Its Authn requests remain dry-run
only; Campaigns wire and activation categories are unchanged. Existing legacy
sync remains until a reviewed receiver/exporter/route cutover; no old-format
adapter is added to generic Authn. The one-time migrate-users DB writer is not a
replacement for this controlled operation and must not be run as part of rollout.

## Acceptance and rollout

Native mTLS + disposable PG tests exercise two unrelated sources, actor/provider
substitution, default dry run and opt-in apply. Store tests cover concurrent writes,
contact/synthetic guards, exact lock compatibility and mutation/audit rollback.
Production configuration, deployment and Redis remain unchanged. Future rollout
must explicitly configure the directory projection/aliases, importer bindings and
matching STS route, deploy receivers before application adapters, and retain old
pins/routes until acceptance. Outbound Telegram-ID JWT signing is preserved.
