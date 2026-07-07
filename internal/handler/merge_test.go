package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestHandleMerge_PreservesOldestAccountID(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		BaseURL:     "https://id.aurum-sky.net",
		FrontendURL: "https://id.aurum-sky.net",
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

	st := mock.New()
	jwtMgr := session.NewManager(kp, cfg.JWT)
	sessMgr := session.NewSessionManager(st, slog.Default(), 24*time.Hour, 7*24*time.Hour, time.Minute)

	now := time.Now()
	olderID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	newerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	st.SeedUser(&store.User{
		ID:          olderID,
		Email:       "older@test.com",
		DisplayName: "Older",
		CreatedAt:   now.Add(-2 * time.Hour),
	})
	st.SeedUser(&store.User{
		ID:          newerID,
		Email:       "newer@test.com",
		DisplayName: "Newer",
		CreatedAt:   now.Add(-time.Hour),
	})
	_ = st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider: "telegram", ProviderUserID: "tg-old", UserID: olderID,
	})
	_ = st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider: "yandex", ProviderUserID: "ya-new", UserID: newerID,
	})

	sourceSess, err := sessMgr.Create(context.Background(), newerID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	rawToken := "merge-token-oldest-wins"
	hash := sha256.Sum256([]byte(rawToken))
	_ = st.CreateMergeRecord(context.Background(), &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  hex.EncodeToString(hash[:]),
		SourceUser: newerID,
		TargetUser: olderID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(5 * time.Minute),
	})

	h := &Handler{
		store:      st,
		sessionMgr: jwtMgr,
		sessMgr:    sessMgr,
		logger:     slog.Default(),
	}
	h.cfg.Store(cfg)

	req := httptest.NewRequest(http.MethodPost, "/auth/merge", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sourceSess.ID})
	req.AddCookie(&http.Cookie{Name: "csar_merge", Value: rawToken})

	w := httptest.NewRecorder()
	h.handleMerge(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["target_user"] != olderID.String() {
		t.Fatalf("target_user = %v, want %s", resp["target_user"], olderID)
	}
	if resp["source_user"] != newerID.String() {
		t.Fatalf("source_user = %v, want %s", resp["source_user"], newerID)
	}

	mergedSource, err := st.GetUserByID(context.Background(), newerID)
	if err != nil {
		t.Fatal(err)
	}
	if mergedSource.MergedInto == nil || *mergedSource.MergedInto != olderID {
		t.Fatalf("expected newer account merged into older, got merged_into=%v", mergedSource.MergedInto)
	}

	accts, err := st.GetOAuthAccountsByUserID(context.Background(), olderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 2 {
		t.Fatalf("expected 2 linked accounts on older user, got %d", len(accts))
	}

	var refreshedSession *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session" && cookie.Value != "" && cookie.Value != sourceSess.ID {
			refreshedSession = cookie
			break
		}
	}
	if refreshedSession == nil {
		t.Fatal("expected refreshed session cookie for canonical target user")
	}
	refreshed, err := st.GetSession(context.Background(), refreshedSession.Value)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.UserID != olderID {
		t.Fatalf("refreshed session user = %s, want %s", refreshed.UserID, olderID)
	}

	revoked, err := st.GetSession(context.Background(), sourceSess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("expected source session to be revoked after merge")
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
