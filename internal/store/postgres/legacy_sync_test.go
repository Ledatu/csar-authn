package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

func legacySyncTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CSAR_TEST_DSN")
	if dsn == "" {
		t.Skip("CSAR_TEST_DSN not set; skipping postgres test")
	}
	ctx := context.Background()
	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateLegacyUserAndLinks_PG(t *testing.T) {
	s := legacySyncTestStore(t)
	ctx := context.Background()
	tg := "tg-" + uuid.NewString()

	created, err := s.CreateLegacyUser(ctx, &store.User{DisplayName: "Anna", Email: "ignored@example.com"}, []store.OAuthAccount{
		{Provider: "telegram", ProviderUserID: tg, ProviderMetadata: map[string]interface{}{"linked_by": "legacy_sync"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUserByID(ctx, created.ID)
	if err != nil || got.DisplayName != "Anna" || got.Email != "" {
		t.Fatalf("user = %+v, %v", got, err)
	}

	if _, err := s.CreateLegacyUser(ctx, &store.User{DisplayName: "Other"}, []store.OAuthAccount{
		{Provider: "yandex", ProviderUserID: "ya-" + uuid.NewString()},
		{Provider: "telegram", ProviderUserID: tg},
	}); !errors.Is(err, store.ErrProviderAlreadyLinked) {
		t.Fatalf("second create with a taken link: err = %v", err)
	}

	ya := "ya-" + uuid.NewString()
	if err := s.LinkLegacyAccount(ctx, &store.OAuthAccount{Provider: "yandex", ProviderUserID: ya, UserID: created.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkLegacyAccount(ctx, &store.OAuthAccount{Provider: "yandex", ProviderUserID: ya, UserID: created.ID}); !errors.Is(err, store.ErrProviderAlreadyLinked) {
		t.Fatalf("repeated link: err = %v", err)
	}
	accounts, err := s.GetOAuthAccountsByUserID(ctx, created.ID)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("accounts = %+v, %v; want the telegram and yandex links only", accounts, err)
	}
}

func TestLegacyUsersSyncLock_PG(t *testing.T) {
	s := legacySyncTestStore(t)
	ctx := context.Background()

	release, ok, err := s.TryLegacyUsersSyncLock(ctx)
	if err != nil || !ok {
		t.Fatalf("first lock: ok = %v, err = %v", ok, err)
	}
	if _, ok, err := s.TryLegacyUsersSyncLock(ctx); err != nil || ok {
		t.Fatalf("second lock while held: ok = %v, err = %v", ok, err)
	}
	release()
	again, ok, err := s.TryLegacyUsersSyncLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock after release: ok = %v, err = %v", ok, err)
	}
	again()
}
