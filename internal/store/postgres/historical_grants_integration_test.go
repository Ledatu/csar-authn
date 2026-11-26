package postgres

import (
	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
	"testing"
)

func TestCallerRevocationCleansHistoricalGrantFamily(t *testing.T) {
	s := auditFixture(t)
	u, err := s.CreateUser(t.Context(), &store.User{DisplayName: "historical owner"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "existing"}
	if err := s.CreateCaller(t.Context(), c, 20); err != nil {
		t.Fatal(err)
	}
	grant := uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO seller_mcp_grants(id,owner_id,client_id,redirect_uri,challenge,code_expires_at,access_hash,expires_at,all_campaigns) VALUES($1,$2,'','','',now(),'historical-access',now()+interval '1 hour',true)`, []any{grant, u.ID}},
		{`INSERT INTO seller_mcp_refresh_tokens(token_hash,grant_id) VALUES('historical-refresh',$1)`, []any{grant}},
		{`INSERT INTO seller_mcp_delegations(token_hash,grant_id,expires_at,discovery_only) VALUES('historical-proof',$1,now()+interval '1 minute',true)`, []any{grant}},
		{`INSERT INTO registered_caller_credentials(credential_kind,credential_id,caller_id,owner_user_id) VALUES('oauth_access',$1,$2,$3)`, []any{grant.String(), c.ID, u.ID}},
	} {
		if _, err := s.pool.Exec(t.Context(), stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RevokeCaller(t.Context(), u.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM seller_mcp_grants WHERE id=$1)+(SELECT count(*) FROM seller_mcp_refresh_tokens WHERE grant_id=$1)+(SELECT count(*) FROM seller_mcp_delegations WHERE grant_id=$1)`, grant).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("historical credentials survived caller revocation", rows, err)
	}
}
