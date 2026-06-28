package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/store"
)

const legacyTelegramTestSecret = "legacy-secret"

func enableLegacyTelegramJWT(h *Handler) {
	cfg := h.cfg.Load()
	cfg.LegacyLogin.TelegramJWT = config.LegacyTelegramJWTConfig{
		Enabled:     true,
		HMACSecret:  legacyTelegramTestSecret,
		MaxTokenAge: config.NewDuration(720 * time.Hour),
	}
	h.cfg.Store(cfg)
}

func legacyTelegramToken(t *testing.T, claims jwt.MapClaims, method jwt.SigningMethod) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(legacyTelegramTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func legacyTelegramClaims(id any) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"id":  id,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func postLegacyTelegramSession(h *Handler, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/auth/legacy/telegram/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "legacy-browser")
	req.RemoteAddr = "203.0.113.10:12345"
	w := httptest.NewRecorder()
	h.handleLegacyTelegramSession(w, req)
	return w
}

func TestLegacyTelegramSession_OK(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	uid := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	st.SeedUser(&store.User{ID: uid, Email: "legacy@test.com", DisplayName: "Legacy"})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "620109623",
		UserID:         uid,
	}); err != nil {
		t.Fatal(err)
	}

	token := legacyTelegramToken(t, legacyTelegramClaims(json.Number("620109623")), jwt.SigningMethodHS256)
	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 1 {
		t.Fatalf("expected session cookie, got %d cookies", len(w.Result().Cookies()))
	}
	if w.Result().Cookies()[0].Name != "session" {
		t.Fatalf("cookie name = %q, want session", w.Result().Cookies()[0].Name)
	}

	sessions, err := st.ListUserSessions(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 created session, got %d", len(sessions))
	}
	if sessions[0].UserAgent != "legacy-browser" || sessions[0].IPAddress != "203.0.113.10" {
		t.Fatalf("unexpected session client data: %+v", sessions[0])
	}
}

func TestLegacyTelegramSession_OKWithoutExpiration(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	uid := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	st.SeedUser(&store.User{ID: uid, Email: "legacy@test.com", DisplayName: "Legacy"})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "416663223",
		UserID:         uid,
	}); err != nil {
		t.Fatal(err)
	}

	token := legacyTelegramToken(t, jwt.MapClaims{
		"id":       json.Number("416663223"),
		"username": "diagen_001",
		"iat":      time.Now().Add(-time.Minute).Unix(),
	}, jwt.SigningMethodHS256)
	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 1 {
		t.Fatalf("expected session cookie, got %d cookies", len(w.Result().Cookies()))
	}
}

func TestLegacyTelegramSession_Disabled(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	token := legacyTelegramToken(t, legacyTelegramClaims(json.Number("620109623")), jwt.SigningMethodHS256)

	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsBadSignature(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyTelegramClaims(json.Number("620109623")))
	signed, err := token.SignedString([]byte("wrong-secret"))
	if err != nil {
		t.Fatal(err)
	}

	w := postLegacyTelegramSession(h, signed)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsWrongAlgorithm(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	token := legacyTelegramToken(t, legacyTelegramClaims(json.Number("620109623")), jwt.SigningMethodHS384)
	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsExpiredToken(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	claims := legacyTelegramClaims(json.Number("620109623"))
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	token := legacyTelegramToken(t, claims, jwt.SigningMethodHS256)

	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsMissingID(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	claims := legacyTelegramClaims(json.Number("620109623"))
	delete(claims, "id")
	token := legacyTelegramToken(t, claims, jwt.SigningMethodHS256)

	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsMissingIssuedAt(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	claims := legacyTelegramClaims(json.Number("620109623"))
	delete(claims, "iat")
	token := legacyTelegramToken(t, claims, jwt.SigningMethodHS256)

	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_RejectsUnknownAccount(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	token := legacyTelegramToken(t, legacyTelegramClaims(json.Number("620109623")), jwt.SigningMethodHS256)
	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLegacyTelegramSession_FollowsMergedUser(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	enableLegacyTelegramJWT(h)

	sourceID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	targetID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	st.SeedUser(&store.User{ID: targetID, Email: "target@test.com", DisplayName: "Target"})
	st.SeedUser(&store.User{
		ID:          sourceID,
		Email:       "source@test.com",
		DisplayName: "Source",
		MergedInto:  &targetID,
	})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "620109623",
		UserID:         sourceID,
	}); err != nil {
		t.Fatal(err)
	}

	token := legacyTelegramToken(t, legacyTelegramClaims(json.Number("620109623")), jwt.SigningMethodHS256)
	w := postLegacyTelegramSession(h, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	sourceSessions, err := st.ListUserSessions(context.Background(), sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceSessions) != 0 {
		t.Fatalf("expected no source sessions, got %d", len(sourceSessions))
	}
	targetSessions, err := st.ListUserSessions(context.Background(), targetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetSessions) != 1 {
		t.Fatalf("expected 1 target session, got %d", len(targetSessions))
	}
}
