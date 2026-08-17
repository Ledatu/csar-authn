package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

var (
	impersonationAdminID  = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	impersonationTargetID = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
)

func allowingAuthzClient() *mockAuthzClient {
	return &mockAuthzClient{
		checkAccessFn: func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
		listSubjectRolesFn: func(_ context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
			return &pb.ListSubjectRolesResponse{}, nil
		},
	}
}

func newImpersonationHandler(t *testing.T, authz *mockAuthzClient) (*Handler, *mock.Store, *session.SessionManager) {
	t.Helper()

	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		BaseURL:                "https://id.aurum-sky.net",
		FrontendURL:            "https://id.aurum-sky.net",
		AllowedRedirectOrigins: []string{"https://id.aurum-sky.net", "https://app.aurum-sky.net"},
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

	st := mock.New()
	sessMgr := session.NewSessionManager(st, slog.Default(), 24*time.Hour, 7*24*time.Hour, time.Minute)

	h := &Handler{
		store:         st,
		sessionMgr:    session.NewManager(kp, cfg.JWT),
		sessMgr:       sessMgr,
		oauthMgr:      oauthMgr,
		authzClient:   &AuthzClient{client: authz, logger: slog.Default()},
		auditRecorder: &mockAuditRecorder{},
		logger:        slog.Default(),
	}
	h.cfg.Store(cfg)

	st.SeedUser(&store.User{ID: impersonationAdminID, Email: "admin@test.com", DisplayName: "Admin"})
	st.SeedUser(&store.User{ID: impersonationTargetID, Email: "target@test.com", DisplayName: "Target"})
	return h, st, sessMgr
}

func adminBearer(t *testing.T, h *Handler) string {
	t.Helper()
	tok, err := h.sessionMgr.IssueToken(impersonationAdminID.String(), "admin@test.com", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func createGrant(t *testing.T, h *Handler, auth func(*http.Request), body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/impersonation", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	auth(req)
	w := httptest.NewRecorder()
	h.handleCreateImpersonationGrant(w, req)
	return w
}

func bearerAuth(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func cookieAuth(sessionID string) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	}
}

func exchangeToken(t *testing.T, h *Handler, exchangeURL string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(exchangeURL)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/impersonate/exchange?"+u.RawQuery, nil)
	req.Header.Set("User-Agent", "impersonation-test-ua")
	w := httptest.NewRecorder()
	h.handleImpersonationExchange(w, req)
	return w
}

func grantExchangeURL(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		ExchangeURL string `json:"exchange_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ExchangeURL == "" {
		t.Fatalf("missing exchange_url in response: %s", w.Body.String())
	}
	return resp.ExchangeURL
}

func TestImpersonation_FullFlow(t *testing.T) {
	h, st, sessMgr := newImpersonationHandler(t, allowingAuthzClient())
	token := adminBearer(t, h)

	w := createGrant(t, h, bearerAuth(token), map[string]string{
		"user_id":      impersonationTargetID.String(),
		"reason":       "ticket SUP-123",
		"redirect_url": "https://app.aurum-sky.net/dashboard",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("grant: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	exchangeURL := grantExchangeURL(t, w)
	if !strings.HasPrefix(exchangeURL, "https://id.aurum-sky.net/auth/impersonate/exchange?token=") {
		t.Fatalf("unexpected exchange URL: %s", exchangeURL)
	}

	ew := exchangeToken(t, h, exchangeURL)
	if ew.Code != http.StatusSeeOther {
		t.Fatalf("exchange: expected 303, got %d: %s", ew.Code, ew.Body.String())
	}
	if loc := ew.Header().Get("Location"); loc != "https://app.aurum-sky.net/dashboard" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}

	var sessCookie *http.Cookie
	for _, c := range ew.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("exchange did not set a session cookie")
	}
	if sessCookie.MaxAge <= 0 || sessCookie.MaxAge > int(time.Hour.Seconds()) {
		t.Fatalf("cookie MaxAge = %d, want (0, 3600]", sessCookie.MaxAge)
	}

	sess, err := st.GetSession(context.Background(), sessCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserID != impersonationTargetID {
		t.Fatalf("session user = %s, want target", sess.UserID)
	}
	if sess.ImpersonatorUserID == nil || *sess.ImpersonatorUserID != impersonationAdminID {
		t.Fatal("session is missing impersonator attribution")
	}
	if sess.ImpersonationReason != "ticket SUP-123" {
		t.Fatalf("session reason = %q", sess.ImpersonationReason)
	}
	if remaining := time.Until(sess.ExpiresAt); remaining > time.Hour+time.Minute {
		t.Fatalf("session TTL too long: %s", remaining)
	}

	// The impersonated session authenticates as the target user.
	validated, err := sessMgr.Validate(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if validated.UserID != impersonationTargetID {
		t.Fatalf("validated user = %s, want target", validated.UserID)
	}
}

func TestImpersonation_ExchangeIsSingleUse(t *testing.T) {
	h, _, _ := newImpersonationHandler(t, allowingAuthzClient())
	token := adminBearer(t, h)

	w := createGrant(t, h, bearerAuth(token), map[string]string{
		"user_id": impersonationTargetID.String(),
		"reason":  "debug",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("grant: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	exchangeURL := grantExchangeURL(t, w)

	if first := exchangeToken(t, h, exchangeURL); first.Code != http.StatusSeeOther {
		t.Fatalf("first exchange: expected 303, got %d", first.Code)
	}
	if second := exchangeToken(t, h, exchangeURL); second.Code != http.StatusGone {
		t.Fatalf("second exchange: expected 410, got %d", second.Code)
	}
}

func TestImpersonation_ExpiredGrantRejected(t *testing.T) {
	h, st, _ := newImpersonationHandler(t, allowingAuthzClient())

	now := time.Now().UTC()
	_ = st.CreateImpersonationGrant(context.Background(), &store.ImpersonationGrant{
		ID:           uuid.New(),
		TokenHash:    hashValue("expired-token"),
		AdminUserID:  impersonationAdminID,
		TargetUserID: impersonationTargetID,
		Reason:       "too late",
		RedirectURL:  "https://id.aurum-sky.net",
		CreatedAt:    now.Add(-2 * time.Minute),
		ExpiresAt:    now.Add(-time.Minute),
	})

	w := exchangeToken(t, h, "https://id.aurum-sky.net/auth/impersonate/exchange?token=expired-token")
	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpersonation_ReasonRequired(t *testing.T) {
	h, _, _ := newImpersonationHandler(t, allowingAuthzClient())
	token := adminBearer(t, h)

	w := createGrant(t, h, bearerAuth(token), map[string]string{
		"user_id": impersonationTargetID.String(),
		"reason":  "   ",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpersonation_TargetWithPlatformRolesRejected(t *testing.T) {
	authz := allowingAuthzClient()
	authz.listSubjectRolesFn = func(_ context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
		if req.Subject != impersonationTargetID.String() {
			t.Errorf("ListSubjectRoles subject = %q, want target", req.Subject)
		}
		return &pb.ListSubjectRolesResponse{Roles: []string{"platform_admin"}}, nil
	}
	h, _, _ := newImpersonationHandler(t, authz)
	token := adminBearer(t, h)

	w := createGrant(t, h, bearerAuth(token), map[string]string{
		"user_id": impersonationTargetID.String(),
		"reason":  "debug",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpersonation_SelfRejected(t *testing.T) {
	h, _, _ := newImpersonationHandler(t, allowingAuthzClient())
	token := adminBearer(t, h)

	w := createGrant(t, h, bearerAuth(token), map[string]string{
		"user_id": impersonationAdminID.String(),
		"reason":  "debug",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpersonation_NoChainingAndNoAdminAccess(t *testing.T) {
	h, _, sessMgr := newImpersonationHandler(t, allowingAuthzClient())

	sess, err := sessMgr.CreateImpersonated(context.Background(),
		impersonationTargetID, impersonationAdminID, "debug", "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	w := createGrant(t, h, cookieAuth(sess.ID), map[string]string{
		"user_id": impersonationTargetID.String(),
		"reason":  "chain attempt",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("chained grant: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	lw := httptest.NewRecorder()
	h.handleListAdminSessions(lw, req)
	if lw.Code != http.StatusForbidden {
		t.Fatalf("admin list: expected 403, got %d: %s", lw.Code, lw.Body.String())
	}
}

func TestImpersonation_SessionDoesNotSlide(t *testing.T) {
	_, st, sessMgr := newImpersonationHandler(t, allowingAuthzClient())

	sess, err := sessMgr.CreateImpersonated(context.Background(),
		impersonationTargetID, impersonationAdminID, "debug", "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	originalExpiry := sess.ExpiresAt

	// Backdate last_seen past the touch threshold; a regular session would slide.
	if err := st.TouchSession(context.Background(), sess.ID, time.Now().Add(-10*time.Minute), originalExpiry); err != nil {
		t.Fatal(err)
	}

	validated, err := sessMgr.Validate(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.ExpiresAt.Equal(originalExpiry) {
		t.Fatalf("impersonated session expiry moved: %s -> %s", originalExpiry, validated.ExpiresAt)
	}
}

func TestImpersonation_ValidateForwardsImpersonatorHeader(t *testing.T) {
	h, _, sessMgr := newImpersonationHandler(t, allowingAuthzClient())

	sess, err := sessMgr.CreateImpersonated(context.Background(),
		impersonationTargetID, impersonationAdminID, "debug", "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/validate", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	w := httptest.NewRecorder()
	h.handleValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-Impersonator-ID"); got != impersonationAdminID.String() {
		t.Fatalf("X-Impersonator-ID = %q, want admin id", got)
	}
	if got := w.Header().Get("X-User-ID"); got != impersonationTargetID.String() {
		t.Fatalf("X-User-ID = %q, want target id", got)
	}
}
