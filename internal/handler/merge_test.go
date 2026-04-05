package handler

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
)

func TestHandleMergeInitiate_SetsMergeAndRedirectCookies(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		BaseURL:                "https://id.aurum-sky.net",
		FrontendURL:            "https://id.aurum-sky.net",
		AllowedRedirectOrigins: []string{"https://id.aurum-sky.net"},
		OAuth: config.OAuthConfig{
			SessionSecret: "0123456789abcdef0123456789abcdef",
			Providers: []config.ProviderConfig{{
				Name:         "yandex",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}},
		},
		Cookie: config.CookieConfig{
			Name:     "session",
			SameSite: "lax",
		},
		JWT: config.JWTConfig{
			Issuer:   "test-issuer",
			Audience: "test-audience",
			TTL:      authnconfig.NewDuration(time.Hour),
		},
	}

	oauthMgr, err := oauth.NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager(kp, cfg.JWT)
	st := mock.New()
	userID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "merge@test.com",
		DisplayName: "Merge Tester",
	})

	token, err := sm.IssueToken(userID.String(), "merge@test.com", "Merge Tester")
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		oauthMgr:   oauthMgr,
		logger:     slog.Default(),
	}
	h.cfg.Store(cfg)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/merge/start/yandex?redirect_url=https%3A%2F%2Fid.aurum-sky.net%2Fconnections",
		nil,
	)
	req.SetPathValue("provider", "yandex")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	h.handleMergeInitiate(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	cookies := w.Result().Cookies()
	assertCookieValue(t, cookies, "csar_intent", "merge")
	assertCookieValue(t, cookies, "csar_merge_target", userID.String())
	assertCookieValue(t, cookies, "csar_redirect", "https://id.aurum-sky.net/connections")
}

func TestHandleMergeInitiate_IgnoresInvalidRedirectURL(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		BaseURL:                "https://id.aurum-sky.net",
		FrontendURL:            "https://id.aurum-sky.net",
		AllowedRedirectOrigins: []string{"https://id.aurum-sky.net"},
		OAuth: config.OAuthConfig{
			SessionSecret: "0123456789abcdef0123456789abcdef",
			Providers: []config.ProviderConfig{{
				Name:         "yandex",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			}},
		},
		Cookie: config.CookieConfig{
			Name:     "session",
			SameSite: "lax",
		},
		JWT: config.JWTConfig{
			Issuer:   "test-issuer",
			Audience: "test-audience",
			TTL:      authnconfig.NewDuration(time.Hour),
		},
	}

	oauthMgr, err := oauth.NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager(kp, cfg.JWT)
	st := mock.New()
	userID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "merge-invalid@test.com",
		DisplayName: "Merge Invalid Redirect",
	})

	token, err := sm.IssueToken(userID.String(), "merge-invalid@test.com", "Merge Invalid Redirect")
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		store:      st,
		sessionMgr: sm,
		oauthMgr:   oauthMgr,
		logger:     slog.Default(),
	}
	h.cfg.Store(cfg)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/merge/start/yandex?redirect_url=https%3A%2F%2Fevil.example%2Fconnections",
		nil,
	)
	req.SetPathValue("provider", "yandex")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	h.handleMergeInitiate(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	cookies := w.Result().Cookies()
	assertCookieValue(t, cookies, "csar_intent", "merge")
	assertCookieValue(t, cookies, "csar_merge_target", userID.String())

	for _, cookie := range cookies {
		if cookie.Name == "csar_redirect" {
			t.Fatalf("unexpected csar_redirect cookie: %q", cookie.Value)
		}
	}
}

func assertCookieValue(t *testing.T, cookies []*http.Cookie, name, want string) {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == name {
			if cookie.Value != want {
				t.Fatalf("cookie %s = %q, want %q", name, cookie.Value, want)
			}
			return
		}
	}

	t.Fatalf("cookie %s not found", name)
}
