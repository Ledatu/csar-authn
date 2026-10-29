package handler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

type apiCredentialTestStore struct {
	*mock.Store
	key       *store.APICredential
	limit     int
	createErr error
}

func (s *apiCredentialTestStore) CreateAPICredential(_ context.Context, key *store.APICredential, limit int) error {
	if s.createErr != nil {
		return s.createErr
	}
	copyKey := *key
	copyKey.Scopes = append([]string(nil), key.Scopes...)
	s.key = &copyKey
	s.limit = limit
	return nil
}
func (s *apiCredentialTestStore) ListAPICredentials(_ context.Context, owner uuid.UUID) ([]store.APICredential, error) {
	if s.key != nil && s.key.OwnerID == owner {
		return []store.APICredential{*s.key}, nil
	}
	return []store.APICredential{}, nil
}
func (s *apiCredentialTestStore) RevokeAPICredential(_ context.Context, owner, id uuid.UUID) (*store.APICredential, error) {
	if s.key == nil || s.key.OwnerID != owner || s.key.ID != id {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	s.key.RevokedAt = &now
	return s.key, nil
}
func (s *apiCredentialTestStore) FindAPICredentialByHash(_ context.Context, hash string) (*store.APICredential, error) {
	if s.key == nil || s.key.TokenHash != hash || s.key.RevokedAt != nil || !s.key.ExpiresAt.After(time.Now()) {
		return nil, store.ErrNotFound
	}
	return s.key, nil
}
func apiKeyScopeHarness(t *testing.T) (*testHarness, *apiCredentialTestStore, *http.Cookie) {
	t.Helper()
	th := newTestHarness(t)
	st := &apiCredentialTestStore{Store: th.store}
	th.handler.store = st
	th.store.SeedUser(&store.User{ID: testUserID})
	th.handler.sessMgr = session.NewSessionManager(st, slog.Default(), time.Hour, time.Hour, time.Minute)
	sess, err := th.handler.sessMgr.Create(context.Background(), testUserID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return th, st, &http.Cookie{Name: "session", Value: sess.ID}
}
func TestAPIKeyScopeConsentAndPermissions(t *testing.T) {
	seller := "32709d54-a113-46f0-ac1c-fc418ab7d1ae"
	cases := []struct {
		name, scopeJSON         string
		wantScopes, wantActions []string
		status                  int
		denied                  string
		authErr                 bool
	}{
		{"legacy omission", "", []string{"adverts:read"}, []string{"massAdvert.read"}, 201, "", false},
		{"explicit adverts", `,"scopes":["adverts:read"]`, []string{"adverts:read"}, []string{"massAdvert.read"}, 201, "", false},
		{"analytics only", `,"scopes":["analytics:read"]`, []string{"analytics:read"}, []string{"analytics.read"}, 201, "", false},
		{"advertising only", `,"scopes":["advertising:read"]`, []string{"advertising:read"}, []string{"massAdvert.read"}, 201, "", false},
		{"all three", `,"scopes":["analytics:read","adverts:read","advertising:read"]`, []string{"advertising:read", "adverts:read", "analytics:read"}, []string{"massAdvert.read", "massAdvert.read", "analytics.read"}, 201, "", false},
		{"advertising denied", `,"scopes":["advertising:read"]`, nil, []string{"massAdvert.read"}, 403, "massAdvert.read", false},
		{"both", `,"scopes":["analytics:read","adverts:read"]`, []string{"adverts:read", "analytics:read"}, []string{"massAdvert.read", "analytics.read"}, 201, "", false},
		{"empty", `,"scopes":[]`, nil, nil, 400, "", false},
		{"null", `,"scopes":null`, nil, nil, 400, "", false},
		{"unknown", `,"scopes":["analytics:write"]`, nil, nil, 400, "", false},
		{"duplicate", `,"scopes":["analytics:read","analytics:read"]`, nil, nil, 400, "", false},
		{"wrong type", `,"scopes":"analytics:read"`, nil, nil, 400, "", false},
		{"analytics denied", `,"scopes":["analytics:read"]`, nil, []string{"analytics.read"}, 403, "analytics.read", false},
		{"second denied", `,"scopes":["adverts:read","analytics:read"]`, nil, []string{"massAdvert.read", "analytics.read"}, 403, "analytics.read", false},
		{"authz failure", `,"scopes":["analytics:read"]`, nil, []string{"analytics.read"}, 503, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			th, st, cookie := apiKeyScopeHarness(t)
			var actions []string
			th.mock.checkAccessFn = func(_ context.Context, r *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
				if r.Subject != testUserID.String() || r.Resource != "campaign_module" || r.ScopeType != "tenant" || r.ScopeId != "wildberries:"+seller {
					t.Fatalf("incorrect permission boundary: %+v", r)
				}
				actions = append(actions, r.Action)
				if tc.authErr {
					return nil, errors.New("unavailable")
				}
				return &pb.CheckAccessResponse{Allowed: r.Action != tc.denied}, nil
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/me/api-keys", strings.NewReader(`{"seller_id":"`+seller+`","label":" analysis "`+tc.scopeJSON+`}`))
			req.AddCookie(cookie)
			req.Header.Set("Origin", "https://seller.aurum-sky.net")
			w := httptest.NewRecorder()
			before := time.Now()
			th.handler.handleCreateAPIKey(w, req)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d; %s", w.Code, tc.status, w.Body.String())
			}
			if !reflect.DeepEqual(actions, tc.wantActions) {
				t.Fatalf("actions %v, want %v", actions, tc.wantActions)
			}
			if tc.status != 201 {
				if st.key != nil {
					t.Fatal("denied request persisted a key")
				}
				return
			}
			var out struct {
				Key   store.APICredential `json:"key"`
				Token string              `json:"token"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.Key.Scopes, tc.wantScopes) || !reflect.DeepEqual(st.key.Scopes, tc.wantScopes) {
				t.Fatalf("scope persistence/response mismatch: %+v %+v", out.Key, st.key)
			}
			digest := sha256.Sum256([]byte(out.Token))
			if st.key.TokenHash != hex.EncodeToString(digest[:]) || st.key.SellerID != seller || st.key.OwnerID != testUserID || st.limit != 5 || st.key.ExpiresAt.Before(before.Add(apiKeyLifetime)) || st.key.ExpiresAt.After(time.Now().Add(apiKeyLifetime)) {
				t.Fatal("credential hashing, binding, cap or lifetime changed")
			}
			hasScopedGrant := strings.Contains(tc.scopeJSON, "analytics:read") || strings.Contains(tc.scopeJSON, "advertising:read")
			if hasScopedGrant && (!strings.HasPrefix(out.Token, apiKeyScopedPrefix) || len(out.Token) != len(apiKeyScopedPrefix)+43) {
				t.Fatal("scoped key lacks versioned token format")
			}
			if hasScopedGrant && strings.HasPrefix(out.Token, apiKeyPrefix) && len(out.Token) == len(apiKeyPrefix)+43 {
				t.Fatal("legacy introspector would accept scoped key")
			}
			if !validAPIKeyFormat(out.Token) || !strings.HasPrefix(out.Token, "aurum_pat_") {
				t.Fatal("new introspector/router prefix contract rejected token")
			}
		})
	}
}
func TestAPIKeyIntrospectionUsesStoredScopes(t *testing.T) {
	for _, scopes := range [][]string{{"adverts:read"}, {"analytics:read"}, {"advertising:read"}, {"adverts:read", "analytics:read"}, {"adverts:read", "analytics:read", "advertising:read"}, nil, {"unknown"}} {
		t.Run(strings.Join(scopes, "+"), func(t *testing.T) {
			th, st, _ := apiKeyScopeHarness(t)
			raw := apiKeyScopedPrefix + strings.Repeat("a", 43)
			digest := sha256.Sum256([]byte(raw))
			st.key = &store.APICredential{ID: uuid.New(), OwnerID: testUserID, SellerID: "seller", Scopes: scopes, TokenHash: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Hour)}
			invoke := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/internal/api-keys/introspect", strings.NewReader(`{"token":"`+raw+`"}`))
				r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "csar-client"}}}}
				w := httptest.NewRecorder()
				th.handler.handleIntrospectAPIKey(w, r)
				return w
			}
			w := invoke()
			if store.ValidateAPICredentialScopes(scopes) != nil {
				if w.Code != 503 {
					t.Fatalf("invalid stored authority returned %d", w.Code)
				}
				return
			}
			var response struct {
				Active   bool     `json:"active"`
				Scopes   []string `json:"scopes"`
				SellerID string   `json:"seller_id"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || !response.Active || !reflect.DeepEqual(response.Scopes, scopes) || response.SellerID != "seller" {
				t.Fatalf("authority changed: %s", w.Body.String())
			}
			revoked := time.Now()
			st.key.RevokedAt = &revoked
			if w = invoke(); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` {
				t.Fatalf("revoked key accepted: %s", w.Body.String())
			}
			st.key.RevokedAt = nil
			st.key.ExpiresAt = time.Now().Add(-time.Second)
			if w = invoke(); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` {
				t.Fatalf("expired key accepted: %s", w.Body.String())
			}
		})
	}
}
