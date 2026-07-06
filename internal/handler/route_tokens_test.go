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
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/secret"

	"github.com/ledatu/csar-authn/internal/store"
)

func TestHandleValidateWithTokens_IssuesTelegramToken(t *testing.T) {
	h, st, sessMgr := newSessionsHandler(t, nil)
	cfg := h.cfg.Load()
	cfg.RouteTokens = map[string]authnconfig.RouteTokenConfig{
		"telegram-webapp": {
			Enabled:   true,
			Algorithm: "HS256",
			Secret:    secret.NewSecret("route-secret"),
			TTL:       authnconfig.NewDuration(5 * time.Minute),
			Issuer:    "csar-authn",
			Audience:  []string{"telegram-webapp"},
			Claims: map[string]authnconfig.ClaimSource{
				"id": {
					Source:   "oauth.telegram.provider_user_id",
					As:       authnconfig.RouteTokenClaimInt,
					Required: boolPtr(true),
				},
			},
			OnMissingClaim: authnconfig.RouteTokenMissingFailClosed,
		},
	}
	h.cfg.Store(cfg)

	uid := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	st.SeedUser(&store.User{ID: uid, Email: "telegram@test.com", DisplayName: "Telegram"})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "620109623",
		UserID:         uid,
	}); err != nil {
		t.Fatal(err)
	}
	sess, err := sessMgr.Create(context.Background(), uid, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(authntokens.ValidateRequest{
		IssueTokens: []authntokens.IssueTokenRequest{{Profile: "telegram-webapp"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/validate", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	w := httptest.NewRecorder()
	h.handleValidateWithTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var resp authntokens.ValidateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("Errors = %#v", resp.Errors)
	}
	if len(resp.Tokens) != 1 {
		t.Fatalf("Tokens len = %d, want 1", len(resp.Tokens))
	}

	parsed, err := jwt.Parse(resp.Tokens[0].Token, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			t.Fatalf("method = %s, want HS256", token.Method.Alg())
		}
		return []byte("route-secret"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["id"] != float64(620109623) {
		t.Fatalf("id = %v", claims["id"])
	}
	if claims["iss"] != "csar-authn" {
		t.Fatalf("iss = %v", claims["iss"])
	}
}

func boolPtr(v bool) *bool {
	return &v
}
