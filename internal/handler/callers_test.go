package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

type callerHTTPStore struct {
	*apiCredentialTestStore
	row *store.Caller
	err error
}

func (s *callerHTTPStore) CreateCaller(_ context.Context, c *store.Caller, _ int) error {
	if s.err != nil {
		return s.err
	}
	copyCaller := *c
	s.row = &copyCaller
	return nil
}
func (s *callerHTTPStore) ListActiveCallers(_ context.Context, owner uuid.UUID) ([]store.Caller, error) {
	if s.row != nil && s.row.OwnerID == owner && s.row.RevokedAt == nil {
		return []store.Caller{*s.row}, nil
	}
	return []store.Caller{}, nil
}
func (s *callerHTTPStore) RevokeCaller(_ context.Context, owner, id uuid.UUID) (*store.Caller, error) {
	if s.row == nil || s.row.ID != id || s.row.OwnerID != owner {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	s.row.RevokedAt = &now
	return s.row, nil
}
func (s *callerHTTPStore) CallerForCredential(_ context.Context, owner uuid.UUID, kind caller.CredentialKind, reference string) (*store.Caller, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.row == nil || s.key == nil || s.key.CallerID == nil || s.key.ID.String() != reference || kind != caller.APIKey {
		return nil, store.ErrNotFound
	}
	return s.row, nil
}

func TestRegisteredAPIKeyIdentityComesFromAuthenticatedToken(t *testing.T) {
	th, keyStore, cookie := apiKeyScopeHarness(t)
	st := &callerHTTPStore{apiCredentialTestStore: keyStore}
	th.handler.store = st
	th.mock.checkAccessFn = func(_ context.Context, r *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		return &pb.CheckAccessResponse{Allowed: r.Subject == testUserID.String() && r.Action == "analytics.read"}, nil
	}
	request := func(path, body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://seller.aurum-sky.net")
		return r
	}
	w := httptest.NewRecorder()
	th.handler.handleCreateCaller(w, request("/auth/me/callers", `{"caller_kind":"agent","label":"worker"}`))
	if w.Code != 201 || st.row == nil || st.row.OwnerID != testUserID {
		t.Fatal("owner registration failed", w.Code)
	}
	w = httptest.NewRecorder()
	th.handler.handleCreateAPIKey(w, request("/auth/me/api-keys", `{"seller_id":"32709d54-a113-46f0-ac1c-fc418ab7d1ae","label":"human-looking label","scopes":["analytics:read"],"caller_id":"`+st.row.ID.String()+`"}`))
	var issued struct{ Token string }
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Token == "" {
		t.Fatal("registered key creation failed", w.Code)
	}
	introspect := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/auth/token/introspect", strings.NewReader(`{"token":"`+issued.Token+`","caller_kind":"human"}`))
		peer := &x509.Certificate{Subject: pkix.Name{CommonName: "csar-client"}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer, {Raw: []byte("general service CA")}}}}
		w := httptest.NewRecorder()
		th.handler.handleIntrospectAPIKey(w, r)
		return w
	}
	w = introspect()
	var response struct {
		Active   bool             `json:"active"`
		Identity *caller.Identity `json:"identity"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.Active || response.Identity == nil ||
		response.Identity.CallerKind != caller.Agent || response.Identity.CallerID != st.row.ID.String() || response.Identity.CredentialID != st.key.ID.String() {
		t.Fatal("token binding lost or client hint trusted", w.Code)
	}
	st.err = store.ErrNotFound
	if w := introspect(); w.Code != 503 {
		t.Fatal("missing registered binding downgraded to legacy", w.Code)
	}
	st.err = errors.New("lookup unavailable")
	if w := introspect(); w.Code != 503 {
		t.Fatal("registry failure became successful unknown identity", w.Code)
	}
	st.err = nil
	now := time.Now()
	st.row.RevokedAt = &now
	w = introspect()
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Active {
		t.Fatal("revoked caller remained active")
	}
}

func TestCallerRegistrationRejectsUntrustedAuthority(t *testing.T) {
	for _, body := range []string{`{"caller_kind":"human","label":"worker"}`, `{"caller_kind":"service","label":"worker"}`,
		`{"caller_kind":"agent","label":"worker","owner_subject":"foreign"}`} {
		th, keys, cookie := apiKeyScopeHarness(t)
		st := &callerHTTPStore{apiCredentialTestStore: keys}
		th.handler.store = st
		r := httptest.NewRequest(http.MethodPost, "/auth/me/callers", strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://seller.aurum-sky.net")
		w := httptest.NewRecorder()
		th.handler.handleCreateCaller(w, r)
		if w.Code != 400 || st.row != nil {
			t.Fatal("untrusted owner/kind persisted", w.Code)
		}
	}
}

func TestSessionIdentityKeepsOwnerAndEffectiveSubjectSeparate(t *testing.T) {
	owner, effective := uuid.New(), uuid.New()
	sess := &store.Session{ID: "secret-bearer-cookie", UserID: effective, ImpersonatorUserID: &owner}
	id := sessionIdentity(sess, &store.User{ID: effective})
	if err := id.Validate(); err != nil || id.CallerKind != caller.Human || id.CallerID != owner.String() || id.EffectiveSubject != effective.String() || id.CredentialID != "" {
		t.Fatal("session identity lost provenance or exposed cookie", err)
	}
}
