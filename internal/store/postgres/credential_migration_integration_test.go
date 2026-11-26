package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func TestGenericMigrationPreservesLegacyAndInterruptedDDL(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.APIKey)
	if err := s.CreateCaller(t.Context(), c, 20); err != nil {
		t.Fatal(err)
	}
	old := &store.APICredential{ID: uuid.New(), OwnerID: g.OwnerID, CallerID: &c.ID, SellerID: "old-seller", Label: "old-key", TokenHash: genericHash(), Prefix: "legacy", ExpiresAt: g.ExpiresAt}
	if err := s.CreateAPICredential(t.Context(), old, 5); err != nil {
		t.Fatal(err)
	}
	mg := uuid.New()
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO seller_mcp_grants(id,owner_id,client_id,redirect_uri,challenge,code_expires_at,access_hash,expires_at,all_campaigns) VALUES($1,$2,'','','',now(),$3,now()+interval '1 hour',true)`, mg, g.OwnerID, genericHash()); err != nil {
		t.Fatal(err)
	}

	if _, err := s.pool.Exec(t.Context(), `INSERT INTO registered_caller_credentials(credential_kind,credential_id,caller_id,owner_user_id) VALUES('oauth_access',$1,$2,$3)`, mg.String(), c.ID, g.OwnerID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE seller_mcp_grants SET client_id='legacy-client',session_access_hash='old-access',access_expires_at=expires_at WHERE id=$1`, mg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO seller_mcp_refresh_tokens(token_hash,grant_id) VALUES('old-refresh',$1);`, mg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO seller_mcp_delegations(token_hash,grant_id,expires_at,discovery_only) VALUES('old-proof',$1,now()+interval '1 minute',true)`, mg); err != nil {
		t.Fatal(err)
	}
	// Restore exactly the pre-030 physical schema; historical migration SQL is reused
	// unchanged. Snapshot IDs, hashes, consent, deadlines, bindings, spent state/audit.
	if _, err := s.pool.Exec(t.Context(), `DROP TABLE credential_authorization_requests,credential_secrets,credential_grants;
 DROP FUNCTION protect_credential_authority(),protect_credential_request();
 DELETE FROM schema_migrations WHERE name='030_universal_credentials'`); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var out string
		err := s.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
 'keys',(SELECT jsonb_agg(to_jsonb(k)) FROM seller_api_credentials k),
 'grants',(SELECT jsonb_agg(to_jsonb(g)) FROM seller_mcp_grants g),
 'refresh',(SELECT jsonb_agg(to_jsonb(r)) FROM seller_mcp_refresh_tokens r),
 'proofs',(SELECT jsonb_agg(to_jsonb(d)) FROM seller_mcp_delegations d),
 'bindings',(SELECT jsonb_agg(to_jsonb(b)) FROM registered_caller_credentials b),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM csar_audit_outbox a))::text`).Scan(&out)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), migrations[len(migrations)-1].Up); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT 1/0`); err == nil {
		t.Fatal("failed to inject interrupted migration")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err := s.pool.QueryRow(t.Context(), `SELECT to_regclass('credential_grants') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("partial migration escaped transaction", err)
	}
	for range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if after := snapshot(); after != before {
		t.Fatal("additive migration rewrote legacy authority or audit")
	}
	if _, err := s.FindAPICredentialByHash(t.Context(), old.TokenHash); err != nil {
		t.Fatal("old key unreadable", err)
	}
}

func TestGenericOAuthAndLegacyShareConnectionCap(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.OAuthAccess)
	if err := s.CreateCaller(t.Context(), c, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO seller_mcp_grants(owner_id,seller_id,client_id,redirect_uri,challenge,code_expires_at,access_hash,expires_at,all_campaigns) SELECT $1,NULL,'','','',now(),('legacy-'||i),now()+interval '1 hour',true FROM generate_series(1,99) AS i`, g.OwnerID); err != nil {
		t.Fatal(err)
	}
	start, results := make(chan struct{}), make(chan error, 2)
	x := genericSecret(&g, store.SecretAccess, g.ExpiresAt)
	go func() { <-start; results <- s.CreateCredentialGrant(t.Context(), &g, []store.CredentialSecret{x}, nil) }()
	other := g
	other.ID = uuid.New()
	otherSecret := genericSecret(&other, store.SecretAccess, other.ExpiresAt)
	go func() {
		<-start
		results <- s.CreateCredentialGrant(t.Context(), &other, []store.CredentialSecret{otherSecret}, nil)
	}()
	close(start)
	successes := 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, store.ErrCredentialConnectionLimit) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("mixed OAuth cap raced", successes)
	}
}

func TestGenericExpiryNoRefreshEscalationAndSameGrantParent(t *testing.T) {
	s := auditFixture(t)
	g, c := genericGrant(t, s, caller.OAuthAccess)
	x := createGeneric(t, s, &g, c)
	// Manual OAuth-audience credentials cannot gain a refresh policy by omission.
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, x), []store.CredentialSecret{genericSecret(&g, store.SecretRefresh, g.ExpiresAt)}); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("manual credential acquired refresh", err)
	}
	proof := genericSecret(&g, store.SecretExchange, g.ExpiresAt.Add(time.Hour))
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, x), []store.CredentialSecret{proof}); !errors.Is(err, store.ErrCredentialInvalid) {
		t.Fatal("proof extended source deadline", err)
	}
	// Trusted fixture models a credential whose fixed lifetime has already ended;
	// neither the hash nor a still-live parent may resurrect it.
	proof = genericSecret(&g, store.SecretExchange, time.Now().Add(30*time.Second))
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, x), []store.CredentialSecret{proof}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `ALTER TABLE credential_secrets DISABLE TRIGGER credential_secret_authority`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_secrets SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute' WHERE id=$1`, proof.ID); err != nil {
		t.Fatal(err)
	}
	assertMissingSecret(t, s, proof)
	if _, err := s.ExchangeCredentialSecret(t.Context(), genericUse(&g, proof), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired proof consumed", err)
	}
	other, cc := genericGrant(t, s, caller.APIKey)
	xx := createGeneric(t, s, &other, cc)
	if _, err := s.pool.Exec(t.Context(), `UPDATE credential_secrets SET parent_secret_id=$2 WHERE id=$1`, proof.ID, xx.ID); err == nil {
		t.Fatal("cross-grant parent reference accepted")
	}
}
