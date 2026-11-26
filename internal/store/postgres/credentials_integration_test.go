package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
)

func genericHash() string {
	sum := sha256.Sum256([]byte(uuid.NewString()))
	return hex.EncodeToString(sum[:])
}
func genericGrant(t *testing.T, s *Store, kind caller.CredentialKind) (store.CredentialGrant, *store.Caller) {
	t.Helper()
	u, err := s.CreateUser(t.Context(), &store.User{DisplayName: "universal owner"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "Workspace client"}
	g := store.CredentialGrant{ID: uuid.New(), SchemaVersion: 1, OwnerID: u.ID, CallerID: c.ID, Kind: kind, Label: "Generic", ExpiresAt: time.Now().Add(time.Hour), Constraints: authntokens.GrantConstraints{Version: 1, ProfileID: "workspace-reader", ProfileRevision: math.MaxUint64, Audience: "https://workspace.example.test/api", Scopes: []string{"facts:read"}, Namespaces: []string{"documents", "datasets"}, Selection: authntokens.ResourceSelection{Mode: authntokens.Selected, Resources: []authntokens.ResourceRef{{Namespace: "documents", ID: "north-branch"}, {Namespace: "datasets", ID: "north-branch"}}}}}
	return g, c
}
func genericSecret(g *store.CredentialGrant, p store.SecretPurpose, expires time.Time) store.CredentialSecret {
	return store.CredentialSecret{ID: uuid.New(), GrantID: g.ID, Purpose: p, FormatVersion: 1, TokenHash: genericHash(), ExpiresAt: expires}
}
func genericUse(g *store.CredentialGrant, x store.CredentialSecret) store.CredentialUse {
	u := store.CredentialUse{Hash: x.TokenHash, Purpose: x.Purpose, FormatVersion: 1, OwnerID: g.OwnerID, CallerID: g.CallerID, ProfileID: g.Constraints.ProfileID, ProfileRevision: g.Constraints.ProfileRevision, Audience: g.Constraints.Audience, Resource: x.Resource}
	if g.ClientBinding != nil {
		u.ClientID = g.ClientBinding.ClientID
		u.RedirectURI = g.ClientBinding.RedirectURI
		u.PKCEChallenge = g.ClientBinding.PKCEChallenge
	}
	return u
}
func createGeneric(t *testing.T, s *Store, g *store.CredentialGrant, c *store.Caller) store.CredentialSecret {
	t.Helper()
	x := genericSecret(g, store.SecretAccess, g.ExpiresAt)
	if err := s.CreateCredentialGrant(t.Context(), g, []store.CredentialSecret{x}, c); err != nil {
		t.Fatal(err)
	}
	return x
}
func assertMissingSecret(t *testing.T, s *Store, x store.CredentialSecret) {
	t.Helper()
	if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("credential remained usable", err)
	}
}

func TestGenericCredentialConsentIsolationAndRevocation(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	x := createGeneric(t, s, &g, c)
	got, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 1)
	if err != nil || !reflect.DeepEqual(got.Grant.Constraints, g.Constraints) {
		t.Fatal("consent/revision did not round trip", err)
	}
	if got.Grant.Constraints.ProfileRevision != math.MaxUint64 {
		t.Fatal("revision truncated")
	}
	var bindings int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM registered_caller_credentials WHERE credential_id=$1`, g.ID.String()).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatal("generic grant gained second authority", err)
	}
	if _, err := s.FindAPICredentialByHash(t.Context(), x.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("legacy reader adopted new token", err)
	}
	if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, store.SecretRefresh, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("purpose fallback", err)
	}
	if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 2); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("format fallback", err)
	}
	for _, assignment := range []string{`owner_user_id=gen_random_uuid()`, `caller_id=gen_random_uuid()`, `expires_at=expires_at+interval '1 hour'`, `constraints=jsonb_set(constraints,'{profile_revision}','1')`, `client_binding='{}'::jsonb`, `label='changed'`} {
		if _, err := s.pool.Exec(t.Context(), `UPDATE credential_grants SET `+assignment+` WHERE id=$1`, g.ID); err == nil {
			t.Fatal("immutable authority changed", assignment)
		}
	}
	if err := s.RevokeCredentialGrant(t.Context(), uuid.New(), g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign revoke", err)
	}
	if err := s.RevokeCredentialGrant(t.Context(), g.OwnerID, g.ID); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, x)
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_grants SET revoked_at=NULL WHERE id=$1`, g.ID); err == nil {
		t.Fatal("revocation cleared")
	}
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM users WHERE id=$1`, g.OwnerID); err == nil {
		t.Fatal("physical deletion discarded grant/audit authority")
	}
}

func TestGenericProofBindingSingleUseAndAuditRollback(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	access := createGeneric(t, s, &g, c)
	discovery := genericSecret(&g, store.SecretDiscovery, time.Now().Add(30*time.Second))
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, access), []store.CredentialSecret{discovery}); err != nil {
		t.Fatal(err)
	}
	resource := genericSecret(&g, store.SecretResource, discovery.ExpiresAt)
	ref := g.Constraints.Selection.Resources[1]
	resource.Resource = &ref
	use := genericUse(&g, discovery)
	for _, bad := range []store.CredentialUse{func() store.CredentialUse { u := use; u.OwnerID = uuid.New(); return u }(), func() store.CredentialUse { u := use; u.CallerID = uuid.New(); return u }(), func() store.CredentialUse { u := use; u.Audience += "/other"; return u }(), func() store.CredentialUse { u := use; u.ProfileRevision--; return u }()} {
		if _, err := s.ExchangeCredentialSecret(t.Context(), bad, []store.CredentialSecret{resource}); !errors.Is(err, store.ErrCredentialInvalid) {
			t.Fatal("substituted authority accepted", err)
		}
	}
	bad := resource
	other := authntokens.ResourceRef{Namespace: "documents", ID: "foreign"}
	bad.Resource = &other
	if _, err := s.ExchangeCredentialSecret(t.Context(), use, []store.CredentialSecret{bad}); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("outside consent", err)
	}
	// Audit failure rolls back both proof consumption and the new proof row.
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_exchange CHECK(convert_from(payload,'UTF8')::jsonb->>'action'<>'credentials.secret.exchange') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), use, []store.CredentialSecret{resource}); err == nil {
		t.Fatal("unaudited exchange committed")
	}
	if _, err := s.FindCredentialSecret(t.Context(), discovery.TokenHash, discovery.Purpose, 1); err != nil {
		t.Fatal("failed exchange consumed proof", err)
	}
	assertMissingSecret(t, s, resource)
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox DROP CONSTRAINT reject_exchange`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), use, []store.CredentialSecret{resource}); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, discovery)
	bound := genericUse(&g, resource)
	wrong := g.Constraints.Selection.Resources[0]
	bound.Resource = &wrong
	if _, err := s.ExchangeCredentialSecret(t.Context(), bound, nil); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("same opaque ID in other namespace accepted", err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			_, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, resource), nil)
			results <- err
		}()
	}
	close(start)
	success := 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("one-use consumption raced", success)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_secrets SET spent_at=NULL WHERE id=$1`, resource.ID); err == nil {
		t.Fatal("spent proof resurrected")
	}
	proof := genericSecret(&g, store.SecretExchange, time.Now().Add(20*time.Second))
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, access), []store.CredentialSecret{proof}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialGrant(t.Context(), g.OwnerID, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, proof), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("proof survived parent revoke", err)
	}
}

func genericOAuth(t *testing.T, s *Store) (store.CredentialGrant, *store.Caller, store.CredentialAuthorizationRequest, store.CredentialSecret) {
	t.Helper()
	g, c := genericGrant(t, s, caller.OAuthAccess)
	g.ClientBinding = &store.CredentialClientBinding{Version: 1, ClientID: "https://client.example.test/id", RedirectURI: "https://client.example.test/callback", RefreshAllowed: true, PKCEChallenge: strings.Repeat("A", 43)}
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := store.CredentialAuthorizationRequest{ID: uuid.NewString(), SchemaVersion: 1, BrowserHash: genericHash(), ClientBinding: *g.ClientBinding, ProfileID: g.Constraints.ProfileID, ProfileRevision: g.Constraints.ProfileRevision, Audience: g.Constraints.Audience, Scopes: g.Constraints.Scopes, Namespaces: g.Constraints.Namespaces, State: "opaque-state", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := s.BeginCredentialAuthorization(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	code := genericSecret(&g, store.SecretCode, now.Add(4*time.Minute))
	return g, c, r, code
}
func TestGenericOAuthApprovalRotationAndReplay(t *testing.T) {
	s := auditFixture(t)
	g, c, r, code := genericOAuth(t, s)
	if _, err := s.CredentialAuthorization(t.Context(), r.ID, genericHash()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("browser binding bypass", err)
	}
	got, err := s.CredentialAuthorization(t.Context(), r.ID, r.BrowserHash)
	if err != nil || got.ProfileRevision != math.MaxUint64 || got.State != r.State {
		t.Fatal("authorization snapshot changed", err)
	}
	original := g.Constraints.Audience
	g.Constraints.Audience += "/wrong"
	if err := s.ApproveCredentialAuthorization(t.Context(), r.ID, r.BrowserHash, &g, code, c); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("audience substituted", err)
	}
	g.Constraints.Audience = original
	if err := s.ApproveCredentialAuthorization(t.Context(), r.ID, r.BrowserHash, &g, code, c); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveCredentialAuthorization(t.Context(), r.ID, r.BrowserHash, &g, code, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("approval replay", err)
	}
	a, refresh := genericSecret(&g, store.SecretAccess, time.Now().Add(30*time.Minute)), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)
	wrong := genericUse(&g, code)
	wrong.PKCEChallenge = strings.Repeat("B", 43)
	if _, err := s.ExchangeCredentialSecret(t.Context(), wrong, []store.CredentialSecret{a, refresh}); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("PKCE binding bypass", err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, code), []store.CredentialSecret{a, refresh}); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, code)
	a2, r2 := genericSecret(&g, store.SecretAccess, a.ExpiresAt), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), []store.CredentialSecret{a2, r2}); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, a)
	// Spent refresh hashes remain replay evidence for the family lifetime even
	// when that individual secret's shorter presentation deadline has passed.
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE credential_secrets DISABLE TRIGGER credential_secret_authority`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_secrets SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`, refresh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE credential_secrets ENABLE TRIGGER credential_secret_authority`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), []store.CredentialSecret{genericSecret(&g, store.SecretAccess, a.ExpiresAt), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)}); !errors.Is(err, store.ErrCredentialReplay) {
		t.Fatal("refresh replay did not revoke", err)
	}
	assertMissingSecret(t, s, a2)
	assertMissingSecret(t, s, r2)
	var count int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM credential_secrets WHERE grant_id=$1 AND purpose='refresh'`, g.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("refresh replay history was discarded", err)
	}
	var leaked bool
	if err := s.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM csar_audit_outbox WHERE convert_from(payload,'UTF8') LIKE '%'||$1||'%' OR convert_from(payload,'UTF8') LIKE '%'||$2||'%')`, a.TokenHash, refresh.TokenHash).Scan(&leaked); err != nil || leaked {
		t.Fatal("secret material in audit", err)
	}
}

func TestGenericOAuthConcurrentRefreshFailsClosed(t *testing.T) {
	s := auditFixture(t)
	g, c, r, code := genericOAuth(t, s)
	if err := s.ApproveCredentialAuthorization(t.Context(), r.ID, r.BrowserHash, &g, code, c); err != nil {
		t.Fatal(err)
	}
	a, refresh := genericSecret(&g, store.SecretAccess, time.Now().Add(30*time.Minute)), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, code), []store.CredentialSecret{a, refresh}); err != nil {
		t.Fatal(err)
	}
	start, results := make(chan struct{}), make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), []store.CredentialSecret{genericSecret(&g, store.SecretAccess, a.ExpiresAt), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)})
			results <- err
		}()
	}
	close(start)
	success, replay := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, store.ErrCredentialReplay):
			replay++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || replay != 1 {
		t.Fatal("refresh race lost replay protection", success, replay)
	}
	assertMissingSecret(t, s, a)
}

func TestGenericCredentialMixedCapsAndCallerRevocation(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	if err := s.CreateCaller(t.Context(), c, 20); err != nil {
		t.Fatal(err)
	}
	var old *store.APICredential
	for range 4 {
		old = &store.APICredential{ID: uuid.New(), OwnerID: g.OwnerID, CallerID: &c.ID, SellerID: "old-seller", Label: "legacy", TokenHash: genericHash(), Prefix: "old", ExpiresAt: g.ExpiresAt}
		if err := s.CreateAPICredential(t.Context(), old, 5); err != nil {
			t.Fatal(err)
		}
	}
	newSecret := genericSecret(&g, store.SecretAccess, g.ExpiresAt)
	start, results := make(chan struct{}), make(chan error, 2)
	go func() {
		<-start
		results <- s.CreateCredentialGrant(t.Context(), &g, []store.CredentialSecret{newSecret}, nil)
	}()
	go func() {
		<-start
		key := *old
		key.ID = uuid.New()
		key.TokenHash = genericHash()
		results <- s.CreateAPICredential(t.Context(), &key, 5)
	}()
	close(start)
	success := 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, store.ErrAPICredentialLimit) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("mixed family cap raced", success)
	}
	// Ensure a generic parent exists even if the old family won the cap race.
	if _, err := s.FindCredentialSecret(t.Context(), newSecret.TokenHash, newSecret.Purpose, 1); errors.Is(err, store.ErrNotFound) {
		if _, err := s.RevokeAPICredential(t.Context(), g.OwnerID, old.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateCredentialGrant(t.Context(), &g, []store.CredentialSecret{newSecret}, nil); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeCaller(t.Context(), g.OwnerID, c.ID); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, newSecret)
	if _, err := s.FindAPICredentialByHash(t.Context(), old.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("legacy key survived caller revoke", err)
	}
}

func TestGenericGrantCreationAndOwnerMergeAuditAtomicity(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	x := genericSecret(&g, store.SecretAccess, g.ExpiresAt)
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_grant CHECK(convert_from(payload,'UTF8')::jsonb->>'target_type'<>'credential_grant')`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCredentialGrant(t.Context(), &g, []store.CredentialSecret{x}, c); err == nil {
		t.Fatal("grant committed without audit")
	}
	var rows int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM registered_callers WHERE id=$1)+(SELECT count(*) FROM credential_grants WHERE id=$2)+(SELECT count(*) FROM credential_secrets WHERE grant_id=$2)`, c.ID, g.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("grant failure left orphan authority", err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox DROP CONSTRAINT reject_grant`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCredentialGrant(t.Context(), &g, []store.CredentialSecret{x}, c); err != nil {
		t.Fatal(err)
	}
	target, err := s.CreateUser(t.Context(), &store.User{DisplayName: "merge target"})
	if err != nil {
		t.Fatal(err)
	}
	outbox := s.outbox
	s.outbox = nil
	if err := s.MergeUsers(t.Context(), target.ID, g.OwnerID); !errors.Is(err, store.ErrCallerAuditRequired) {
		t.Fatal("merge bypassed generic audit", err)
	}
	s.outbox = outbox
	if err := s.MergeUsers(t.Context(), target.ID, g.OwnerID); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, x)
	var owner uuid.UUID
	var revoked *time.Time
	if err := s.pool.QueryRow(t.Context(), `SELECT owner_user_id,revoked_at FROM credential_grants WHERE id=$1`, g.ID).Scan(&owner, &revoked); err != nil || owner != g.OwnerID || revoked == nil {
		t.Fatal("merge rebound consent", err)
	}
	// Model rollback to an older writer: soft merge alone must also deny new grants.
	other, cc := genericGrant(t, s, caller.APIKey)
	xx := createGeneric(t, s, &other, cc)
	if _, err := s.pool.Exec(t.Context(), `UPDATE users SET merged_into=$2 WHERE id=$1`, other.OwnerID, target.ID); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, xx)
}

func TestGenericCredentialCorruptRowsDeny(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	x := createGeneric(t, s, &g, c)
	raw, err := json.Marshal(g.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE credential_grants DISABLE TRIGGER credential_grant_authority`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_grants SET constraints=constraints||'{"future_required":true}'::jsonb WHERE id=$1`, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 1); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("unsupported stored structure became default", err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_grants SET constraints=$2 WHERE id=$1`, g.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE credential_grants DROP CONSTRAINT credential_grants_schema_version_check; UPDATE credential_grants SET schema_version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 1); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("unsupported row version accepted", err)
	}
}

func TestGenericLifecycleAuditFailureRollsBackEveryAuthority(t *testing.T) {
	s := auditFixture(t)
	g, c, r, code := genericOAuth(t, s)
	if err := s.ApproveCredentialAuthorization(t.Context(), r.ID, r.BrowserHash, &g, code, c); err != nil {
		t.Fatal(err)
	}
	access, refresh := genericSecret(&g, store.SecretAccess, time.Now().Add(30*time.Minute)), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, code), []store.CredentialSecret{access, refresh}); err != nil {
		t.Fatal(err)
	}
	pending, pc, req, pcode := genericOAuth(t, s)
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_mutation CHECK(convert_from(payload,'UTF8')::jsonb->>'action' NOT LIKE 'credentials.%') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialGrant(t.Context(), g.OwnerID, g.ID); err == nil {
		t.Fatal("unaudited grant revoke committed")
	}
	if _, err := s.RevokeCaller(t.Context(), g.OwnerID, c.ID); err == nil {
		t.Fatal("unaudited caller revoke committed")
	}
	if err := s.ApproveCredentialAuthorization(t.Context(), req.ID, req.BrowserHash, &pending, pcode, pc); err == nil {
		t.Fatal("unaudited approval committed")
	}
	if _, err := s.CredentialAuthorization(t.Context(), req.ID, req.BrowserHash); err != nil {
		t.Fatal("failed approval consumed request", err)
	}
	var orphan int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM credential_grants WHERE id=$1)+(SELECT count(*) FROM registered_callers WHERE id=$2)`, pending.ID, pc.ID).Scan(&orphan); err != nil || orphan != 0 {
		t.Fatal("failed approval left authority", orphan, err)
	}
	nextAccess, nextRefresh := genericSecret(&g, store.SecretAccess, access.ExpiresAt), genericSecret(&g, store.SecretRefresh, g.ExpiresAt)
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), []store.CredentialSecret{nextAccess, nextRefresh}); err == nil {
		t.Fatal("unaudited refresh committed")
	}
	for _, x := range []store.CredentialSecret{access, refresh} {
		if _, err := s.FindCredentialSecret(t.Context(), x.TokenHash, x.Purpose, 1); err != nil {
			t.Fatal("failed mutation changed authority", err)
		}
	}
	assertMissingSecret(t, s, nextAccess)
	assertMissingSecret(t, s, nextRefresh)
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox DROP CONSTRAINT reject_mutation`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), []store.CredentialSecret{nextAccess, nextRefresh}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_replay CHECK(convert_from(payload,'UTF8')::jsonb->>'action'<>'credentials.refresh.replay') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), nil); err == nil || errors.Is(err, store.ErrCredentialReplay) {
		t.Fatal("replay reported committed revocation without audit", err)
	}
	if _, err := s.FindCredentialSecret(t.Context(), nextAccess.TokenHash, nextAccess.Purpose, 1); err != nil {
		t.Fatal("failed replay audit mutated family", err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE csar_audit_outbox DROP CONSTRAINT reject_replay`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, refresh), nil); !errors.Is(err, store.ErrCredentialReplay) {
		t.Fatal("retry failed to revoke replayed family", err)
	}
	assertMissingSecret(t, s, nextAccess)
}
