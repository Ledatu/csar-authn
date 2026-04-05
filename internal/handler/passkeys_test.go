package handler

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
)

func TestDeletePasskey_RejectsLastLoginMethod(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager(kp, config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	})
	st := mock.New()
	userID := uuid.New()
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "passkey-only@test.com",
		DisplayName: "Passkey Only",
	})
	passkeyRecord := &store.Passkey{
		ID:           uuid.New(),
		UserID:       userID,
		Label:        "Only Passkey",
		CredentialID: []byte("cred-only"),
		PublicKey:    []byte("pk-only"),
	}
	if err := st.CreatePasskey(context.Background(), passkeyRecord); err != nil {
		t.Fatal(err)
	}

	token, err := sm.IssueToken(userID.String(), "passkey-only@test.com", "Passkey Only")
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		logger:     slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/passkeys/"+passkeyRecord.ID.String(), nil)
	req.SetPathValue("passkey_id", passkeyRecord.ID.String())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleDeletePasskey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDeletePasskey_AllowsDeleteWhenAnotherMethodExists(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager(kp, config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	})
	st := mock.New()
	userID := uuid.New()
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "multi@test.com",
		DisplayName: "Multi Method",
	})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "tg-1",
		UserID:         userID,
	}); err != nil {
		t.Fatal(err)
	}
	passkeyRecord := &store.Passkey{
		ID:           uuid.New(),
		UserID:       userID,
		Label:        "Delete Me",
		CredentialID: []byte("cred-delete"),
		PublicKey:    []byte("pk-delete"),
	}
	if err := st.CreatePasskey(context.Background(), passkeyRecord); err != nil {
		t.Fatal(err)
	}

	token, err := sm.IssueToken(userID.String(), "multi@test.com", "Multi Method")
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		logger:     slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/passkeys/"+passkeyRecord.ID.String(), nil)
	req.SetPathValue("passkey_id", passkeyRecord.ID.String())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleDeletePasskey(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusNoContent, w.Body.String())
	}

	methods, err := st.CountUserLoginMethods(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if methods != 1 {
		t.Fatalf("CountUserLoginMethods() = %d, want 1", methods)
	}
}
