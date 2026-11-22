package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func boundKey(t *testing.T, s *Store, owner uuid.UUID, id *uuid.UUID) *store.APICredential {
	t.Helper()
	hash := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("a", 32)
	k := &store.APICredential{ID: uuid.New(), OwnerID: owner, CallerID: id, SellerID: uuid.NewString(), Label: "synthetic",
		TokenHash: hash, Prefix: "test", Scopes: []string{store.APIKeyScopeAnalyticsRead}, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateAPICredential(context.Background(), k, 5); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCredentialBindingRotationLegacyAndRevoke(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	u, err := s.CreateUser(ctx, &store.User{DisplayName: "token caller"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "agent"}
	if err := s.CreateCaller(ctx, c, 20); err != nil {
		t.Fatal(err)
	}
	legacy := boundKey(t, s, u.ID, nil)
	if _, err := s.CallerForCredential(ctx, u.ID, caller.APIKey, legacy.ID.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("legacy credential was classified", err)
	}
	one, two := boundKey(t, s, u.ID, &c.ID), boundKey(t, s, u.ID, &c.ID)
	for _, key := range []*store.APICredential{one, two} {
		read, err := s.FindAPICredentialByHash(ctx, key.TokenHash)
		if err != nil || read.CallerID == nil || *read.CallerID != c.ID {
			t.Fatal("authenticated key lost binding", err)
		}
		registered, err := s.CallerForCredential(ctx, u.ID, caller.APIKey, read.ID.String())
		if err != nil || registered.ID != c.ID || registered.Kind != caller.Agent {
			t.Fatal("credential rotation changed caller", err)
		}
	}
	if _, err := s.CallerForCredential(ctx, uuid.New(), caller.APIKey, one.ID.String()); !errors.Is(err, store.ErrCallerBinding) {
		t.Fatal("foreign owner resolved registered caller", err)
	}
	if _, err := s.RevokeCaller(ctx, u.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	for _, key := range []*store.APICredential{one, two} {
		if _, err := s.FindAPICredentialByHash(ctx, key.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("revoked caller retained active credential", err)
		}
	}
	if _, err := s.FindAPICredentialByHash(ctx, legacy.TokenHash); err != nil {
		t.Fatal("unrelated legacy credential was revoked", err)
	}
	registered, err := s.CallerForCredential(ctx, u.ID, caller.APIKey, one.ID.String())
	if err != nil || registered.RevokedAt == nil {
		t.Fatal("revoked binding downgraded to legacy", err)
	}
}

func TestForeignBindingAndUnauditedRevokeRollback(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	u, err := s.CreateUser(ctx, &store.User{DisplayName: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := s.CreateUser(ctx, &store.User{DisplayName: "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Application, Label: "app"}
	if err := s.CreateCaller(ctx, c, 20); err != nil {
		t.Fatal(err)
	}
	key := boundKey(t, s, u.ID, &c.ID)
	bad := *key
	bad.ID, bad.OwnerID, bad.TokenHash = uuid.New(), foreign.ID, strings.Repeat("b", 64)
	if err := s.CreateAPICredential(ctx, &bad, 5); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign registration accepted", err)
	}
	if _, err := s.FindAPICredentialByHash(ctx, bad.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed binding left a credential", err)
	}
	if _, err := s.pool.Exec(ctx, `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_revoke CHECK(convert_from(payload,'UTF8')::jsonb->>'action'<>'credentials.caller.revoke')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeCaller(ctx, u.ID, c.ID); err == nil {
		t.Fatal("caller revoked without audit")
	}
	if _, err := s.FindAPICredentialByHash(ctx, key.TokenHash); err != nil {
		t.Fatal("unaudited revoke changed credential", err)
	}
}
