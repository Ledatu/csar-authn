package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestUnlinkProvider_AuditRecorded(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	}
	sm := session.NewManager(kp, jwtCfg)
	st := mock.New()
	auditSt := &mockAuditRecorder{}

	h := &Handler{
		store:         st,
		sessionMgr:    sm,
		auditRecorder: auditSt,
		logger:        slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	userID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "unlink@test.com",
		DisplayName: "Unlink Tester",
	})
	for _, acct := range []*store.OAuthAccount{
		{Provider: "telegram", ProviderUserID: "tg-1", UserID: userID},
		{Provider: "yandex", ProviderUserID: "ya-1", UserID: userID},
	} {
		if err := st.CreateOAuthAccount(context.Background(), acct); err != nil {
			t.Fatal(err)
		}
	}

	token, err := sm.IssueToken(userID.String(), "unlink@test.com", "Unlink Tester")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/providers/yandex", nil)
	req.SetPathValue("provider", "yandex")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleUnlinkProvider(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	count, err := st.CountOAuthAccounts(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 linked account after unlink, got %d", count)
	}

	events := auditSt.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "oauth_provider.unlink" {
		t.Errorf("action = %q, want %q", events[0].Action, "oauth_provider.unlink")
	}
	if events[0].Actor != userID.String() {
		t.Errorf("actor = %q, want %q", events[0].Actor, userID.String())
	}
	if events[0].TargetType != "oauth_provider" {
		t.Errorf("target_type = %q, want %q", events[0].TargetType, "oauth_provider")
	}
	if events[0].TargetID != "yandex" {
		t.Errorf("target_id = %q, want %q", events[0].TargetID, "yandex")
	}
}

func TestDeleteMeEmail_AuditRecorded(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	}
	sm := session.NewManager(kp, jwtCfg)
	st := mock.New()
	auditSt := &mockAuditRecorder{}

	h := &Handler{
		store:         st,
		sessionMgr:    sm,
		auditRecorder: auditSt,
		logger:        slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	userID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "first@example.com",
		DisplayName: "Email Unlink Tester",
	})
	for _, email := range []string{"first@example.com", "second@example.com"} {
		if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
			Provider:       store.EmailProvider,
			ProviderUserID: email,
			UserID:         userID,
			Email:          email,
			EmailVerified:  true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	token, err := sm.IssueToken(userID.String(), "first@example.com", "Email Unlink Tester")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/emails", strings.NewReader(`{"email":"FIRST@example.com"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleDeleteMeEmail(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := st.GetOAuthAccount(context.Background(), store.EmailProvider, "first@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected first email to be removed, got %v", err)
	}
	user, err := st.GetUserByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "second@example.com" {
		t.Fatalf("primary email = %q, want second@example.com", user.Email)
	}

	events := auditSt.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "email.disconnect" {
		t.Errorf("action = %q, want %q", events[0].Action, "email.disconnect")
	}
	if events[0].TargetType != "email" {
		t.Errorf("target_type = %q, want %q", events[0].TargetType, "email")
	}
	if events[0].TargetID != "first@example.com" {
		t.Errorf("target_id = %q, want %q", events[0].TargetID, "first@example.com")
	}
}

func TestDeleteMeEmail_RejectsLastLoginMethod(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	}
	sm := session.NewManager(kp, jwtCfg)
	st := mock.New()

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		logger:     slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	userID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "only-email@example.com",
		DisplayName: "Only Email",
	})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       store.EmailProvider,
		ProviderUserID: "only-email@example.com",
		UserID:         userID,
		Email:          "only-email@example.com",
		EmailVerified:  true,
	}); err != nil {
		t.Fatal(err)
	}

	token, err := sm.IssueToken(userID.String(), "only-email@example.com", "Only Email")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/emails", strings.NewReader(`{"email":"only-email@example.com"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleDeleteMeEmail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnlinkProvider_RejectsLastLoginMethod(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	}
	sm := session.NewManager(kp, jwtCfg)
	st := mock.New()

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		logger:     slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	userID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "single-unlink@test.com",
		DisplayName: "Single Unlink",
	})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider: "telegram", ProviderUserID: "tg-only", UserID: userID,
	}); err != nil {
		t.Fatal(err)
	}

	token, err := sm.IssueToken(userID.String(), "single-unlink@test.com", "Single Unlink")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/providers/telegram", nil)
	req.SetPathValue("provider", "telegram")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleUnlinkProvider(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
