package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

func TestSessionValidationMetadataAndExpiry(t *testing.T) {
	h, st, sessions := newSessionsHandler(t, nil)
	uid := uuid.New()
	st.SeedUser(&store.User{ID: uid, Email: "session@example.test"})
	sess, err := sessions.Create(context.Background(), uid, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/auth/validate", strings.NewReader(`{}`))
			r.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
			w := httptest.NewRecorder()
			var id *caller.Identity
			var expiry time.Time
			if method == http.MethodGet {
				h.handleValidate(w, r)
				id, err = gatewayctx.CallerFromHeaders(w.Header())
				if err != nil {
					t.Fatal(err)
				}
				expiry, err = time.Parse(time.RFC3339Nano, w.Header().Get(authntokens.HeaderSessionExpiresAt))
				if err != nil {
					t.Fatal(err)
				}
				if w.Body.Len() != 0 {
					t.Fatal("GET contract gained a response body")
				}
			} else {
				h.handleValidateWithTokens(w, r)
				var body authntokens.ValidateResponse
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				id, expiry = body.Identity, body.ExpiresAt
			}
			if w.Code != http.StatusOK || id == nil || id.CallerKind != caller.Human || id.OwnerSubject != uid.String() || id.EffectiveSubject != uid.String() || id.CredentialID != "" || !expiry.Equal(sess.ExpiresAt) {
				t.Fatalf("incorrect validated session metadata: status=%d", w.Code)
			}
			if strings.Contains(w.Body.String(), sess.ID) || strings.Contains(w.Header().Get(gatewayctx.HeaderCaller), sess.ID) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("session bearer exposed or response cacheable")
			}
		})
	}
}
