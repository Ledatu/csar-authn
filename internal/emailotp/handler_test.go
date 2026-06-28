package emailotp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/authnconfig"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

type fakeSender struct {
	code string
	err  error
}

func (s *fakeSender) SendOTP(_ context.Context, _ string, code string) error {
	s.code = code
	return s.err
}

func testConfig() *authnconfig.Config {
	return &authnconfig.Config{
		Cookie: authnconfig.CookieConfig{
			Name:     "csar_session",
			Domain:   "localhost",
			Secure:   false,
			SameSite: "lax",
		},
		EmailOTP: &authnconfig.EmailOTPConfig{
			Enabled:            true,
			CodeTTL:            authnconfig.NewDuration(5 * time.Minute),
			MaxPendingPerIP:    3,
			MaxPendingPerEmail: 3,
			MaxAttempts:        3,
			Cooldown:           authnconfig.NewDuration(0),
			SenderAddress:      "login@example.com",
			Subject:            "Code",
		},
	}
}

func testHandler() (*Handler, *mock.Store, *fakeSender) {
	st := mock.New()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sessMgr := session.NewSessionManager(st, logger, 24*time.Hour, 7*24*time.Hour, time.Minute)
	sender := &fakeSender{}
	h := NewHandler(st, sessMgr, sender, testConfig(), logger)
	return h, st, sender
}

func postJSON(t *testing.T, url string, body map[string]string) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandleStartDoesNotReturnCode(t *testing.T) {
	h, _, sender := testHandler()

	req := postJSON(t, "/auth/email-otp/start", map[string]string{"email": "USER@Example.COM"})
	w := httptest.NewRecorder()
	h.HandleStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if sender.code == "" {
		t.Fatal("expected code to be sent")
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["code"] != nil {
		t.Fatal("start response must not include the raw OTP code")
	}
	if resp["challenge_id"] == nil {
		t.Fatal("expected challenge_id")
	}
}

func TestHandleStartSenderError(t *testing.T) {
	h, _, sender := testHandler()
	sender.err = errors.New("postbox unavailable")

	req := postJSON(t, "/auth/email-otp/start", map[string]string{"email": "user@example.com"})
	w := httptest.NewRecorder()
	h.HandleStart(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
}

func TestHandleVerifyLoginCreatesSession(t *testing.T) {
	h, st, sender := testHandler()

	startReq := postJSON(t, "/auth/email-otp/start", map[string]string{"email": "user@example.com"})
	startW := httptest.NewRecorder()
	h.HandleStart(startW, startReq)
	if startW.Code != http.StatusOK {
		t.Fatalf("start status = %d; body = %s", startW.Code, startW.Body.String())
	}
	var startResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(startW.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}

	verifyReq := postJSON(t, "/auth/email-otp/verify", map[string]string{
		"challenge_id": startResp.ChallengeID,
		"code":         sender.code,
	})
	verifyW := httptest.NewRecorder()
	h.HandleVerify(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200; body = %s", verifyW.Code, verifyW.Body.String())
	}
	if len(verifyW.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
	if _, err := st.GetOAuthAccount(context.Background(), providerEmail, "user@example.com"); err != nil {
		t.Fatalf("expected email account link: %v", err)
	}
}

func TestHandleVerifyWrongCodeAttemptLimit(t *testing.T) {
	h, _, sender := testHandler()

	startReq := postJSON(t, "/auth/email-otp/start", map[string]string{"email": "user@example.com"})
	startW := httptest.NewRecorder()
	h.HandleStart(startW, startReq)
	var startResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(startW.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if sender.code == "" {
		t.Fatal("expected sent code")
	}

	for i := 0; i < 2; i++ {
		req := postJSON(t, "/auth/email-otp/verify", map[string]string{
			"challenge_id": startResp.ChallengeID,
			"code":         "000000",
		})
		w := httptest.NewRecorder()
		h.HandleVerify(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, w.Code)
		}
	}

	req := postJSON(t, "/auth/email-otp/verify", map[string]string{
		"challenge_id": startResp.ChallengeID,
		"code":         "000000",
	})
	w := httptest.NewRecorder()
	h.HandleVerify(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("final attempt status = %d, want 429", w.Code)
	}
}

func TestHandleVerifyLink(t *testing.T) {
	h, st, sender := testHandler()
	user, err := st.CreateUser(context.Background(), &store.User{
		ID:          uuid.New(),
		Email:       "existing@example.com",
		DisplayName: "Existing",
	})
	if err != nil {
		t.Fatal(err)
	}
	sess := &store.Session{
		ID:         "session-id",
		UserID:     user.ID,
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	startReq := postJSON(t, "/auth/email-otp/start", map[string]string{"email": "new@example.com"})
	startReq.AddCookie(&http.Cookie{Name: h.cfg.Cookie.Name, Value: sess.ID})
	startW := httptest.NewRecorder()
	h.HandleStart(startW, startReq)
	var startResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(startW.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}

	verifyReq := postJSON(t, "/auth/email-otp/verify", map[string]string{
		"challenge_id": startResp.ChallengeID,
		"code":         sender.code,
	})
	verifyReq.AddCookie(&http.Cookie{Name: h.cfg.Cookie.Name, Value: sess.ID})
	verifyW := httptest.NewRecorder()
	h.HandleVerify(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200; body = %s", verifyW.Code, verifyW.Body.String())
	}
	acct, err := st.GetOAuthAccount(context.Background(), providerEmail, "new@example.com")
	if err != nil {
		t.Fatalf("expected linked account: %v", err)
	}
	if acct.UserID != user.ID {
		t.Fatalf("linked user = %s, want %s", acct.UserID, user.ID)
	}
}
