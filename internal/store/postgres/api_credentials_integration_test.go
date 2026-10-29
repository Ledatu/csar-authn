package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
)

// Uses auditFixture's unique schema and strict localhost csar_audit_test guard.
func TestAPICredentialScopesMigrationAndLifecycle(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, &store.User{DisplayName: "scope migration"})
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the immediately preceding schema to prove existing keys are not broadened.
	if _, err = s.pool.Exec(ctx, `ALTER TABLE seller_api_credentials DROP COLUMN scopes`); err != nil {
		t.Fatal(err)
	}
	oldID := uuid.New()
	oldHash := strings.Repeat("b", 64)
	if _, err = s.pool.Exec(ctx, `INSERT INTO seller_api_credentials (id,owner_user_id,seller_id,label,token_hash,token_prefix,expires_at) VALUES ($1,$2,'seller','legacy',$3,'legacy-prefix',now()+interval '1 hour')`, oldID, owner.ID, oldHash); err != nil {
		t.Fatal(err)
	}
	var migrationSQL string
	for _, migration := range migrations {
		if migration.Name == "021_seller_api_credential_scopes" {
			migrationSQL = migration.Up
		}
	}
	if migrationSQL == "" {
		t.Fatal("scope migration missing")
	}
	for range 2 {
		if _, err = s.pool.Exec(ctx, migrationSQL); err != nil {
			t.Fatalf("scope migration is not idempotent: %v", err)
		}
	}
	legacy, err := s.FindAPICredentialByHash(ctx, oldHash)
	if err != nil || !reflect.DeepEqual(legacy.Scopes, []string{"adverts:read"}) {
		t.Fatalf("legacy scope backfill changed authority: %+v %v", legacy, err)
	}
	// Old binaries omit scopes on INSERT and must continue receiving only adverts.
	if _, err = s.pool.Exec(ctx, `INSERT INTO seller_api_credentials (id,owner_user_id,seller_id,label,token_hash,token_prefix,expires_at) VALUES ($1,$2,'seller','old writer',$3,'old-writer',now()+interval '1 hour')`, uuid.New(), owner.ID, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	oldWriter, err := s.FindAPICredentialByHash(ctx, strings.Repeat("c", 64))
	if err != nil || !reflect.DeepEqual(oldWriter.Scopes, []string{"adverts:read"}) {
		t.Fatalf("legacy writer broadened: %+v %v", oldWriter, err)
	}
	key := &store.APICredential{ID: uuid.New(), OwnerID: owner.ID, SellerID: "seller", Label: "analytics", TokenHash: strings.Repeat("d", 64), Prefix: "v2-test-prefix", Scopes: []string{"analytics:read"}, ExpiresAt: time.Now().Add(time.Hour)}
	if err = s.CreateAPICredential(ctx, key, 5); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindAPICredentialByHash(ctx, key.TokenHash)
	if err != nil || !reflect.DeepEqual(got.Scopes, key.Scopes) || got.SellerID != key.SellerID {
		t.Fatalf("persisted authority mismatch: %+v %v", got, err)
	}
	items, err := s.ListAPICredentials(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.ID == key.ID {
			found = reflect.DeepEqual(item.Scopes, key.Scopes)
		}
	}
	if !found {
		t.Fatal("list lost issued scope consent")
	}
	for _, bad := range []string{`'{}'::text[]`, `ARRAY['analytics:write']`, `ARRAY['analytics:read','analytics:read']`, `ARRAY[NULL]::text[]`} {
		if _, err = s.pool.Exec(ctx, `UPDATE seller_api_credentials SET scopes=`+bad+` WHERE id=$1`, key.ID); err == nil {
			t.Fatalf("invalid scope array accepted: %s", bad)
		}
	}
	if _, err = s.RevokeAPICredential(ctx, uuid.New(), key.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another owner can revoke", err)
	}
	if _, err = s.RevokeAPICredential(ctx, owner.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.FindAPICredentialByHash(ctx, key.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoked scoped key active", err)
	}
	if _, err = s.pool.Exec(ctx, `UPDATE seller_api_credentials SET expires_at=now()-interval '1 second' WHERE id=$1`, oldID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.FindAPICredentialByHash(ctx, oldHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired legacy key active", err)
	}
}

func TestAdvertisingScopeMigrationDoesNotBroadenIssuedKeys(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, &store.User{DisplayName: "advertising consent"})
	if err != nil {
		t.Fatal(err)
	}
	keys := []*store.APICredential{}
	for i, scopes := range [][]string{{"adverts:read"}, {"analytics:read"}, {"adverts:read", "analytics:read"}} {
		key := &store.APICredential{ID: uuid.New(), OwnerID: owner.ID, SellerID: "seller", Label: "prior consent", TokenHash: strings.Repeat(string(rune('e'+i)), 64), Prefix: "test-prefix", Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.CreateAPICredential(ctx, key, 5); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	// Restore 021's constraint, then exercise the additive 022 migration twice.
	if _, err := s.pool.Exec(ctx, `ALTER TABLE seller_api_credentials DROP CONSTRAINT seller_api_credentials_scopes_check`); err != nil {
		t.Fatal(err)
	}
	var next string
	for _, migration := range migrations {
		if migration.Name == "021_seller_api_credential_scopes" {
			if _, err := s.pool.Exec(ctx, migration.Up); err != nil {
				t.Fatal(err)
			}
		}
		if migration.Name == "022_seller_api_advertising_scope" {
			next = migration.Up
		}
	}
	if next == "" {
		t.Fatal("advertising scope migration missing")
	}
	for range 2 {
		if _, err := s.pool.Exec(ctx, next); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range keys {
		current, err := s.FindAPICredentialByHash(ctx, key.TokenHash)
		if err != nil || !reflect.DeepEqual(current.Scopes, key.Scopes) {
			t.Fatalf("migration broadened existing consent: %+v %v", current, err)
		}
	}
	key := &store.APICredential{ID: uuid.New(), OwnerID: owner.ID, SellerID: "seller", Label: "advertising only", TokenHash: strings.Repeat("h", 64), Prefix: "v2-test-prefix", Scopes: []string{"advertising:read"}, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateAPICredential(ctx, key, 5); err != nil {
		t.Fatal(err)
	}
	current, err := s.FindAPICredentialByHash(ctx, key.TokenHash)
	if err != nil || !reflect.DeepEqual(current.Scopes, key.Scopes) {
		t.Fatal("advertising authority lost", err)
	}
	for _, bad := range []string{`'{}'::text[]`, `ARRAY['advertising:write']`, `ARRAY['advertising:read','advertising:read']`, `ARRAY['analytics:read','advertising:read','analytics:read']`, `ARRAY[NULL]::text[]`} {
		if _, err := s.pool.Exec(ctx, `UPDATE seller_api_credentials SET scopes=`+bad+` WHERE id=$1`, key.ID); err == nil {
			t.Fatalf("invalid scope array accepted: %s", bad)
		}
	}
	key.ID = uuid.New()
	key.TokenHash = strings.Repeat("i", 64)
	key.Scopes = []string{"adverts:read", "analytics:read", "advertising:read"}
	if err := s.CreateAPICredential(ctx, key, 5); err != nil {
		t.Fatal("all explicit grants failed", err)
	}
	current, err = s.FindAPICredentialByHash(ctx, key.TokenHash)
	if err != nil || !reflect.DeepEqual(current.Scopes, key.Scopes) {
		t.Fatal("combined consent changed", err)
	}
	// Default still excludes both newer scopes, including for old application writers.
	var defaultScopes []string
	if err := s.pool.QueryRow(ctx, `INSERT INTO seller_api_credentials(id,owner_user_id,seller_id,label,token_hash,token_prefix,expires_at) VALUES($1,$2,'seller','old writer',$3,'old',now()+interval '1 hour') RETURNING scopes`, uuid.New(), owner.ID, strings.Repeat("j", 64)).Scan(&defaultScopes); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(defaultScopes, []string{"adverts:read"}) {
		t.Fatalf("default broadened: %v", defaultScopes)
	}
}
