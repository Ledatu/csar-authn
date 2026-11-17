package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
)

// Exercise the real SQL/scan contracts after retiring every avatar column.
// auditFixture accepts only an isolated localhost test database and random schema.
func TestIdentityWithoutAvatarColumns(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `ALTER TABLE users DROP COLUMN avatar_url, DROP COLUMN avatar_storage_key, DROP COLUMN avatar_preview_storage_key, DROP COLUMN avatar_master_storage_key;
 ALTER TABLE oauth_accounts DROP COLUMN avatar_url`)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, &store.User{Email: "blobatar@example.test", Phone: "+79990000001", DisplayName: "Identity"})
	if err != nil {
		t.Fatal(err)
	}
	for name, lookup := range map[string]func() (*store.User, error){
		"id":    func() (*store.User, error) { return s.GetUserByID(ctx, u.ID) },
		"email": func() (*store.User, error) { return s.GetUserByEmail(ctx, u.Email) },
		"phone": func() (*store.User, error) { return s.GetUserByPhone(ctx, u.Phone) },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := lookup()
			if err != nil || got.ID != u.ID {
				t.Fatalf("lookup: %+v %v", got, err)
			}
		})
	}
	acct := &store.OAuthAccount{Provider: "telegram", ProviderUserID: "998877", UserID: u.ID, DisplayName: "Telegram"}
	if err := s.CreateOAuthAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	acct.DisplayName = "Updated"
	if err := s.UpdateOAuthAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOAuthAccount(ctx, "telegram", acct.ProviderUserID)
	if err != nil || got.DisplayName != "Updated" {
		t.Fatalf("oauth: %+v %v", got, err)
	}
	accounts, err := s.GetOAuthAccountsByUserID(ctx, u.ID)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts: %+v %v", accounts, err)
	}
	byID, err := s.GetUsersByIDs(ctx, []uuid.UUID{u.ID})
	if err != nil || len(byID) != 1 || byID[0].ID != u.ID {
		t.Fatalf("directory: %+v %v", byID, err)
	}
	byProvider, err := s.GetUsersByProviderIDs(ctx, "telegram", []string{acct.ProviderUserID})
	if err != nil || len(byProvider) != 1 || byProvider[0].ID != u.ID {
		t.Fatalf("provider directory: %+v %v", byProvider, err)
	}
	matches, err := s.SearchUsers(ctx, store.UserSearchParams{Query: "Identity", Limit: 10})
	if err != nil || len(matches) != 1 {
		t.Fatalf("search: %+v %v", matches, err)
	}
	legacy, err := s.CreateLegacyUser(ctx, &store.User{DisplayName: "Legacy"}, []store.OAuthAccount{{Provider: "telegram", ProviderUserID: "998878"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MergeUsers(ctx, u.ID, legacy.ID); err != nil {
		t.Fatal(err)
	}
	merged, err := s.GetUserByID(ctx, legacy.ID)
	if err != nil || merged.MergedInto == nil || *merged.MergedInto != u.ID {
		t.Fatalf("merge: %+v %v", merged, err)
	}
	login := &store.OAuthAccount{Provider: "yandex", ProviderUserID: "test-identity", Email: "new@example.test", EmailVerified: true}
	created, result, err := s.FindOrCreateUser(ctx, login, login.Email, "", "New Identity")
	if err != nil || result != store.ResultCreatedNewUser {
		t.Fatalf("signup: %+v %v %v", created, result, err)
	}
	existing, result, err := s.FindOrCreateUser(ctx, login, login.Email, "", "New Identity")
	if err != nil || result != store.ResultExistingLogin || existing.ID != created.ID {
		t.Fatalf("login: %+v %v %v", existing, result, err)
	}
}
