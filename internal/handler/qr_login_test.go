package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func newQRLoginHandler(t *testing.T) (*Handler, *mock.Store, *session.SessionManager, *config.Config) {
	t.Helper()

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
		QRLogin: config.QRLoginConfig{
			TTL:             authnconfig.NewDuration(2 * time.Minute),
			MaxPendingPerIP: 3,
			CleanupInterval: authnconfig.NewDuration(5 * time.Minute),
		},
	}

	oauthMgr, err := oauth.NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	jwtMgr := session.NewManager(kp, cfg.JWT)
	st := mock.New()
	sessMgr := session.NewSessionManager(st, slog.Default(), 24*time.Hour, 7*24*time.Hour, time.Minute)

	h := &Handler{
		store:         st,
		sessionMgr:    jwtMgr,
		sessMgr:       sessMgr,
		oauthMgr:      oauthMgr,
		auditRecorder: &mockAuditRecorder{},
		logger:        slog.Default(),
	}
	h.cfg.Store(cfg)
	return h, st, sessMgr, cfg
}

type qrLoginStartResponse struct {
	RequestID        string `json:"request_id"`
	QRURL            string `json:"qr_url"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

func startQRLogin(t *testing.T, h *Handler, st *mock.Store, redirectURL, userAgent, remoteAddr string) (qrLoginStartResponse, *http.Cookie, string, *store.LoginHandoff) {
	t.Helper()

	body, err := json.Marshal(map[string]string{"redirect_url": redirectURL})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/qr-login/start", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.RemoteAddr = remoteAddr

	w := httptest.NewRecorder()
	h.handleQRLoginStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp qrLoginStartResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	var stateCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == qrLoginStateCookieName {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("expected QR login state cookie")
	}

	qrURL, err := url.Parse(resp.QRURL)
	if err != nil {
		t.Fatal(err)
	}
	token := qrURL.Query().Get("token")
	if token == "" {
		t.Fatal("expected QR URL token")
	}

	handoff, err := st.GetLoginHandoffByScanToken(context.Background(), hashValue(token))
	if err != nil {
		t.Fatal(err)
	}

	return resp, stateCookie, token, handoff
}

func seedAuthenticatedSession(t *testing.T, st *mock.Store, sessMgr *session.SessionManager, userID uuid.UUID, email, displayName string) *http.Cookie {
	t.Helper()

	st.SeedUser(&store.User{
		ID:          userID,
		Email:       email,
		DisplayName: displayName,
	})
	sess, err := sessMgr.Create(context.Background(), userID, "Phone Safari", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "session", Value: sess.ID}
}

func TestQRLoginStartAndStatus(t *testing.T) {
	h, st, _, _ := newQRLoginHandler(t)

	resp, stateCookie, _, handoff := startQRLogin(
		t,
		h,
		st,
		"https://id.aurum-sky.net/overview",
		"Desktop Chrome",
		"203.0.113.5:4321",
	)

	if resp.RequestID != handoff.ID.String() {
		t.Fatalf("request_id = %q, want %q", resp.RequestID, handoff.ID.String())
	}
	if handoff.RedirectURL != "https://id.aurum-sky.net/overview" {
		t.Fatalf("redirect_url = %q", handoff.RedirectURL)
	}
	if handoff.DesktopUserAgent != "Desktop Chrome" {
		t.Fatalf("user_agent = %q", handoff.DesktopUserAgent)
	}
	if handoff.DesktopIPAddress != "203.0.113.5" {
		t.Fatalf("ip_address = %q", handoff.DesktopIPAddress)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/qr-login/status/"+handoff.ID.String(), nil)
	req.SetPathValue("id", handoff.ID.String())
	req.AddCookie(stateCookie)
	w := httptest.NewRecorder()
	h.handleQRLoginStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != loginHandoffStatusPending {
		t.Fatalf("status = %q, want %q", body.Status, loginHandoffStatusPending)
	}
}

func TestQRLoginStart_TooManyPendingForIP(t *testing.T) {
	h, st, _, _ := newQRLoginHandler(t)

	for i := 0; i < 3; i++ {
		startQRLogin(
			t,
			h,
			st,
			"https://id.aurum-sky.net/overview",
			"Desktop Chrome",
			"203.0.113.9:4321",
		)
	}

	body, err := json.Marshal(map[string]string{"redirect_url": "https://id.aurum-sky.net/overview"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/qr-login/start", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:9999"
	w := httptest.NewRecorder()
	h.handleQRLoginStart(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusTooManyRequests, w.Body.String())
	}
}

func TestQRLoginApproveAndComplete(t *testing.T) {
	h, st, sessMgr, _ := newQRLoginHandler(t)

	_, stateCookie, token, handoff := startQRLogin(
		t,
		h,
		st,
		"https://id.aurum-sky.net/overview",
		"Desktop Start",
		"203.0.113.10:5555",
	)

	userID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	phoneCookie := seedAuthenticatedSession(t, st, sessMgr, userID, "qr@example.com", "QR Tester")

	approveBody, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		t.Fatal(err)
	}
	approveReq := httptest.NewRequest(http.MethodPost, "/auth/qr-login/approve", bytes.NewReader(approveBody))
	approveReq.Header.Set("Content-Type", "application/json")
	approveReq.AddCookie(phoneCookie)
	approveW := httptest.NewRecorder()
	h.handleQRLoginApprove(approveW, approveReq)

	if approveW.Code != http.StatusNoContent {
		t.Fatalf("approve status = %d, want %d: %s", approveW.Code, http.StatusNoContent, approveW.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/auth/qr-login/status/"+handoff.ID.String(), nil)
	statusReq.SetPathValue("id", handoff.ID.String())
	statusReq.AddCookie(stateCookie)
	statusW := httptest.NewRecorder()
	h.handleQRLoginStatus(statusW, statusReq)

	var statusBody struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(statusW.Body.Bytes(), &statusBody); err != nil {
		t.Fatal(err)
	}
	if statusBody.Status != loginHandoffStatusApproved {
		t.Fatalf("status = %q, want %q", statusBody.Status, loginHandoffStatusApproved)
	}

	completeReq := httptest.NewRequest(http.MethodPost, "/auth/qr-login/complete/"+handoff.ID.String(), nil)
	completeReq.SetPathValue("id", handoff.ID.String())
	completeReq.Header.Set("User-Agent", "Desktop Complete")
	completeReq.RemoteAddr = "198.51.100.20:4444"
	completeReq.AddCookie(stateCookie)
	completeW := httptest.NewRecorder()
	h.handleQRLoginComplete(completeW, completeReq)

	if completeW.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want %d: %s", completeW.Code, http.StatusOK, completeW.Body.String())
	}

	var completeBody struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(completeW.Body.Bytes(), &completeBody); err != nil {
		t.Fatal(err)
	}
	if completeBody.RedirectURL != handoff.RedirectURL {
		t.Fatalf("redirect_url = %q, want %q", completeBody.RedirectURL, handoff.RedirectURL)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range completeW.Result().Cookies() {
		if cookie.Name == "session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after completion")
	}

	sess, err := st.GetSession(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserID != userID {
		t.Fatalf("session user_id = %s, want %s", sess.UserID, userID)
	}
	if sess.UserAgent != "Desktop Complete" {
		t.Fatalf("session user_agent = %q, want %q", sess.UserAgent, "Desktop Complete")
	}
	if sess.IPAddress != "198.51.100.20" {
		t.Fatalf("session ip_address = %q, want %q", sess.IPAddress, "198.51.100.20")
	}

	updated, err := st.GetLoginHandoffStatusForDesktop(context.Background(), handoff.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != loginHandoffStatusConsumed {
		t.Fatalf("handoff status = %q, want %q", updated.Status, loginHandoffStatusConsumed)
	}
}

func TestQRLoginDeny(t *testing.T) {
	h, st, sessMgr, _ := newQRLoginHandler(t)

	_, stateCookie, token, handoff := startQRLogin(
		t,
		h,
		st,
		"https://id.aurum-sky.net/overview",
		"Desktop Start",
		"203.0.113.10:5555",
	)

	userID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	phoneCookie := seedAuthenticatedSession(t, st, sessMgr, userID, "deny@example.com", "Deny Tester")

	denyBody, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		t.Fatal(err)
	}
	denyReq := httptest.NewRequest(http.MethodPost, "/auth/qr-login/deny", bytes.NewReader(denyBody))
	denyReq.Header.Set("Content-Type", "application/json")
	denyReq.AddCookie(phoneCookie)
	denyW := httptest.NewRecorder()
	h.handleQRLoginDeny(denyW, denyReq)

	if denyW.Code != http.StatusNoContent {
		t.Fatalf("deny status = %d, want %d: %s", denyW.Code, http.StatusNoContent, denyW.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/auth/qr-login/status/"+handoff.ID.String(), nil)
	statusReq.SetPathValue("id", handoff.ID.String())
	statusReq.AddCookie(stateCookie)
	statusW := httptest.NewRecorder()
	h.handleQRLoginStatus(statusW, statusReq)

	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(statusW.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != loginHandoffStatusDenied {
		t.Fatalf("status = %q, want %q", body.Status, loginHandoffStatusDenied)
	}
}

func TestQRLoginStatusRejectsMismatchedDesktopCookie(t *testing.T) {
	h, st, _, _ := newQRLoginHandler(t)

	_, _, _, handoff := startQRLogin(
		t,
		h,
		st,
		"https://id.aurum-sky.net/overview",
		"Desktop Start",
		"203.0.113.10:5555",
	)

	req := httptest.NewRequest(http.MethodGet, "/auth/qr-login/status/"+handoff.ID.String(), nil)
	req.SetPathValue("id", handoff.ID.String())
	req.AddCookie(&http.Cookie{Name: qrLoginStateCookieName, Value: "wrong"})
	w := httptest.NewRecorder()
	h.handleQRLoginStatus(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}
