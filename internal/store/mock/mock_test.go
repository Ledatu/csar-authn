package mock_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func TestFindOrCreateUser_NewUser(t *testing.T) {
	s := mock.New()
	acct := &store.OAuthAccount{
		Provider:       "google",
		ProviderUserID: "g-1",
		Email:          "alice@example.com",
		EmailVerified:  true,
	}

	user, result, err := s.FindOrCreateUser(context.Background(), acct, "alice@example.com", "", "Alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if result != store.ResultCreatedNewUser {
		t.Fatalf("expected ResultCreatedNewUser, got %d", result)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", user.Email)
	}
}

func TestFindOrCreateUser_ExistingOAuthLogin(t *testing.T) {
	s := mock.New()
	acct := &store.OAuthAccount{
		Provider:       "google",
		ProviderUserID: "g-1",
		Email:          "alice@example.com",
		EmailVerified:  true,
	}

	user1, _, _ := s.FindOrCreateUser(context.Background(), acct, "alice@example.com", "", "Alice", "")

	acct2 := &store.OAuthAccount{
		Provider:       "google",
		ProviderUserID: "g-1",
		Email:          "alice@example.com",
		EmailVerified:  true,
		AccessToken:    "new-token",
	}
	user2, result, err := s.FindOrCreateUser(context.Background(), acct2, "alice@example.com", "", "Alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if result != store.ResultExistingLogin {
		t.Fatalf("expected ResultExistingLogin, got %d", result)
	}
	if user2.ID != user1.ID {
		t.Fatal("expected same user ID on repeat login")
	}
}

func TestFindOrCreateUser_VerifiedEmailAutoLink(t *testing.T) {
	s := mock.New()
	existingUser := &store.User{
		ID:    uuid.New(),
		Email: "bob@example.com",
	}
	s.SeedUser(existingUser)

	acct := &store.OAuthAccount{
		Provider:       "github",
		ProviderUserID: "gh-1",
		Email:          "bob@example.com",
		EmailVerified:  true,
	}

	user, result, err := s.FindOrCreateUser(context.Background(), acct, "bob@example.com", "", "Bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if result != store.ResultLinkedToExisting {
		t.Fatalf("expected ResultLinkedToExisting, got %d", result)
	}
	if user.ID != existingUser.ID {
		t.Fatal("expected to auto-link to existing user by verified email")
	}
}

func TestFindOrCreateUser_UnverifiedEmailConflict_NoPhone(t *testing.T) {
	s := mock.New()
	existingUser := &store.User{
		ID:    uuid.New(),
		Email: "carol@example.com",
	}
	s.SeedUser(existingUser)

	acct := &store.OAuthAccount{
		Provider:       "discord",
		ProviderUserID: "d-1",
		Email:          "carol@example.com",
		EmailVerified:  false,
	}

	_, _, err := s.FindOrCreateUser(context.Background(), acct, "carol@example.com", "", "Carol", "")
	if !errors.Is(err, store.ErrUnverifiedEmailConflict) {
		t.Fatalf("expected ErrUnverifiedEmailConflict, got %v", err)
	}
}

func TestFindOrCreateUser_UnverifiedEmail_PhoneFallback(t *testing.T) {
	s := mock.New()
	existingUser := &store.User{
		ID:    uuid.New(),
		Email: "dave@example.com",
		Phone: "+1234567890",
	}
	s.SeedUser(existingUser)

	acct := &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "t-1",
		Email:          "dave@example.com",
		EmailVerified:  false,
	}

	user, result, err := s.FindOrCreateUser(context.Background(), acct, "dave@example.com", "+1234567890", "Dave", "")
	if err != nil {
		t.Fatalf("expected phone fallback to succeed, got %v", err)
	}
	if result != store.ResultLinkedToExisting {
		t.Fatalf("expected ResultLinkedToExisting, got %d", result)
	}
	if user.ID != existingUser.ID {
		t.Fatal("expected to link to existing user via phone fallback")
	}
}

func TestFindOrCreateUser_PhoneMatch(t *testing.T) {
	s := mock.New()
	existingUser := &store.User{
		ID:    uuid.New(),
		Phone: "+9876543210",
	}
	s.SeedUser(existingUser)

	acct := &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "t-2",
	}

	user, result, err := s.FindOrCreateUser(context.Background(), acct, "", "+9876543210", "TeleUser", "")
	if err != nil {
		t.Fatal(err)
	}
	if result != store.ResultLinkedToExisting {
		t.Fatalf("expected ResultLinkedToExisting, got %d", result)
	}
	if user.ID != existingUser.ID {
		t.Fatal("expected to link to existing user via phone")
	}
}

func TestFindOrCreateUser_Idempotent(t *testing.T) {
	s := mock.New()
	acct := &store.OAuthAccount{
		Provider:       "google",
		ProviderUserID: "g-2",
		Email:          "eve@example.com",
		EmailVerified:  true,
	}

	u1, r1, _ := s.FindOrCreateUser(context.Background(), acct, "eve@example.com", "", "Eve", "")
	u2, r2, _ := s.FindOrCreateUser(context.Background(), acct, "eve@example.com", "", "Eve", "")
	u3, r3, _ := s.FindOrCreateUser(context.Background(), acct, "eve@example.com", "", "Eve", "")

	if r1 != store.ResultCreatedNewUser {
		t.Fatalf("first call: expected ResultCreatedNewUser, got %d", r1)
	}
	if r2 != store.ResultExistingLogin || r3 != store.ResultExistingLogin {
		t.Fatal("subsequent calls should return ResultExistingLogin")
	}
	if u1.ID != u2.ID || u2.ID != u3.ID {
		t.Fatal("all calls should return the same user")
	}
}

func TestLinkOAuthAccount(t *testing.T) {
	s := mock.New()
	user := &store.User{ID: uuid.New(), Email: "frank@example.com"}
	s.SeedUser(user)

	acct := &store.OAuthAccount{
		Provider:       "github",
		ProviderUserID: "gh-2",
		Email:          "frank@example.com",
		EmailVerified:  true,
	}

	if err := s.LinkOAuthAccount(context.Background(), user.ID, acct); err != nil {
		t.Fatal(err)
	}

	// Linking the same account to the same user should update, not error.
	acct.AccessToken = "updated"
	if err := s.LinkOAuthAccount(context.Background(), user.ID, acct); err != nil {
		t.Fatal(err)
	}

	// Linking to a different user should fail.
	otherUser := &store.User{ID: uuid.New(), Email: "other@example.com"}
	s.SeedUser(otherUser)

	err := s.LinkOAuthAccount(context.Background(), otherUser.ID, acct)
	if !errors.Is(err, store.ErrProviderAlreadyLinked) {
		t.Fatalf("expected ErrProviderAlreadyLinked, got %v", err)
	}
}
