package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

type manualMCPTestStore struct {
	store.MCPGrantStore
	in *store.MCPManualToken
}

func (s *manualMCPTestStore) CreateManualMCP(_ context.Context, in store.MCPManualToken) (store.MCPGrant, error) {
	s.in = &in
	return store.MCPGrant{ID: uuid.New(), ExpiresAt: time.Now().Add(time.Duration(in.Hours) * time.Hour)}, nil
}

func TestManualMCPRequiresOwnerOriginAndBoundedConsent(t *testing.T) {
	for _, tc := range []struct {
		name, origin, body, auth string
		status                   int
		session                  bool
	}{
		{"owner", sellerOrigin, `{"all_campaigns":true,"hours":24,"caller_kind":"agent","caller_label":"Analyst"}`, "", 201, true},
		{"dev owner", "https://dev-seller.aurum-sky.net:3005", `{"all_campaigns":true,"hours":1}`, "", 201, true},
		{"cross origin", "https://attacker.invalid", `{"all_campaigns":true,"hours":1}`, "", 403, true},
		{"no origin", "", `{"all_campaigns":true,"hours":1}`, "", 403, true},
		{"no session", sellerOrigin, `{"all_campaigns":true,"hours":1}`, "", 401, false},
		{"bearer owner", sellerOrigin, `{"all_campaigns":true,"hours":1}`, "Bearer unsupported", 401, true},
		{"overlong", sellerOrigin, `{"all_campaigns":true,"hours":169}`, "", 400, true},
		{"empty selection", sellerOrigin, `{"hours":1}`, "", 400, true},
		{"wrong purpose", sellerOrigin, `{"all_campaigns":true,"hours":1,"caller_kind":"human"}`, "", 400, true},
		{"extra scope", sellerOrigin, `{"all_campaigns":true,"hours":1,"scope":"write"}`, "", 400, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th, _, cookie := apiKeyScopeHarness(t)
			st := &manualMCPTestStore{}
			o := sellerOAuth{Handler: th.handler, grants: st}
			r := httptest.NewRequest("POST", "/oauth/mcp/tokens", strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", "application/json")
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.session {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			o.createManualToken(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if tc.status != 201 {
				if st.in != nil {
					t.Fatal("rejected request reached issuer")
				}
				return
			}
			if w.Header().Get("Cache-Control") != "no-store" || st.in == nil || st.in.OwnerID != testUserID || st.in.NewCaller == nil {
				t.Fatal("missing owner, caller or no-store")
			}
			if tc.name == "owner" && st.in.NewCaller.Kind != caller.Agent {
				t.Fatal("owner purpose lost")
			}
			var result struct {
				Token string `json:"access_token"`
				Scope string `json:"scope"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(result.Token, "aurum_mcp_") || hashValue(result.Token) != st.in.AccessHash || result.Scope != store.APIKeyScopeAnalyticsRead {
				t.Fatal("wrong resource token")
			}
		})
	}
}
