package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func TestAutomaticCallerAndCredentialShareRollback(t *testing.T) {
	s := auditFixture(t)
	u, err := s.CreateUser(t.Context(), &store.User{DisplayName: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	old := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Application, Label: "Existing"}
	if err := s.CreateCaller(t.Context(), old, 20); err != nil {
		t.Fatal(err)
	}
	fresh := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "New"}
	key := &store.APICredential{ID: uuid.New(), OwnerID: u.ID, NewCaller: fresh, SellerID: uuid.NewString(), Label: "key", TokenHash: strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("a", 32), Prefix: "fixture", Scopes: []string{store.APIKeyScopeAnalyticsRead}, ExpiresAt: time.Now().Add(time.Hour)}
	// Force a binding failure after the new caller and credential were inserted.
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO registered_caller_credentials(credential_kind,credential_id,caller_id,owner_user_id) VALUES('api_key',$1,$2,$3)`, key.ID.String(), old.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPICredential(t.Context(), key, 5); err == nil {
		t.Fatal("conflicting binding succeeded")
	}
	var rows int
	if err := s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM registered_callers WHERE id=$1)+(SELECT count(*) FROM seller_api_credentials WHERE id=$2)`, fresh.ID, key.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed binding left an orphan caller or credential", rows, err)
	}
	key.ID, key.TokenHash = uuid.New(), strings.ReplaceAll(uuid.NewString(), "-", "")+strings.Repeat("b", 32)
	if err := s.CreateAPICredential(t.Context(), key, 5); err != nil {
		t.Fatal(err)
	}
	bound, err := s.CallerForCredential(t.Context(), u.ID, caller.APIKey, key.ID.String())
	if err != nil || bound.ID != fresh.ID || bound.Kind != caller.Agent {
		t.Fatal("automatic API credential binding failed", err)
	}
	if _, err := s.RevokeCaller(t.Context(), u.ID, fresh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindAPICredentialByHash(t.Context(), key.TokenHash); err == nil {
		t.Fatal("caller revoke left a new API credential usable")
	}
}
