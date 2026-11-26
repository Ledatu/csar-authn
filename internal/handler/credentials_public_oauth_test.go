package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type publicCredentialFixture struct {
	*credentialFixture
	cache    *redis.Client
	clientID string
}

func newPublicCredentialFixture(t *testing.T) *publicCredentialFixture {
	t.Helper()
	f := newCredentialFixture(t)
	f.u.cfg.PublicOAuth = &authnconfig.CredentialPublicOAuth{Version: 1, Enabled: true, DynamicClients: true, AuthorizationEndpoint: "https://api.example.test/oauth/credentials/authorize", TokenEndpoint: "https://api.example.test/oauth/credentials/token", RegistrationEndpoint: "https://api.example.test/oauth/credentials/register", Profiles: []authnconfig.CredentialOAuthProfile{{ProfileID: "workspace", ResourceAliases: []string{"https://workspace.example.test/"}}}}
	server := miniredis.RunT(t)
	cache := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = cache.Close() })
	client := &http.Client{Transport: credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://client.example.test/id" {
			t.Error("unexpected metadata destination", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"client_id":"https://client.example.test/id","client_name":"Self-declared app","redirect_uris":["http://127.0.0.1:4000/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`))}, nil
	})}
	source, err := f.u.h.sharedPublicClients(cache, client)
	if err != nil {
		t.Fatal(err)
	}
	f.u.clients = source
	// Both registrations of the same public implementation share the same slots,
	// singleflight, cache and protected admission keys; never create a new stack.
	again, err := f.u.h.sharedPublicClients(cache, client)
	if err != nil || again != source {
		t.Fatal("public aliases split admission")
	}
	return &publicCredentialFixture{credentialFixture: f, cache: cache, clientID: "https://client.example.test/id"}
}
func (f *publicCredentialFixture) start(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:4999/callback"}, "scope": {"facts:read"}, "resource": {"https://workspace.example.test/"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(strings.Repeat("A", 43))}, "code_challenge_method": {"S256"}, "state": {"correlation"}}
	r := httptest.NewRequest("GET", "/oauth/credentials/authorize?"+q.Encode(), nil)
	r.TLS = f.tls
	w := httptest.NewRecorder()
	f.u.publicAuthorize(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatal("standard authorize", w.Code, w.Body)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Scheme+"://"+location.Host+location.Path != f.u.cfg.ConsentURL {
		t.Fatal("untrusted consent redirect", err)
	}
	id := location.Query().Get("credential_request")
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == f.u.cfg.ConsentCookieName && cookie.HttpOnly && cookie.Secure {
			return id, cookie
		}
	}
	t.Fatal("missing browser binding")
	return "", nil
}
func (f *publicCredentialFixture) mutate(t *testing.T, path string, body any, browser *http.Cookie, fn http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(data))
	r.Header.Set("Origin", "https://console.example.test")
	r.TLS = f.tls
	r.AddCookie(f.cookie)
	r.AddCookie(browser)
	w := httptest.NewRecorder()
	fn(w, r)
	return w
}
func TestPublicOAuthCIMDConsentTokenAndRefreshPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	id, browser := f.start(t)
	request, err := f.st.CredentialAuthorization(t.Context(), id, hashValue(browser.Value))
	if err != nil || request.ClientBinding.Version != 2 || request.ClientBinding.ClientName != "Self-declared app" || request.ClientBinding.Resource != "https://workspace.example.test/" {
		t.Fatal("snapshot missing", request, err)
	}
	info := httptest.NewRequest("GET", "/oauth/credentials/requests/"+id, nil)
	info.SetPathValue("request_id", id)
	info.AddCookie(browser)
	infoW := httptest.NewRecorder()
	f.u.authorizationInfo(infoW, info)
	if infoW.Code != 200 || !strings.Contains(infoW.Body.String(), "Self-declared app") {
		t.Fatal(infoW.Code, infoW.Body)
	}
	input := map[string]any{"request_id": id, "profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "selected", "resources": []map[string]string{{"namespace": "workspace", "id": "north-branch"}}}, "label": "Public OAuth", "caller_kind": "application", "ttl_seconds": 3600}
	w := f.mutate(t, "/oauth/credentials/approve", input, browser, f.u.approveAuthorization)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var approved struct {
		Redirect string    `json:"redirect"`
		ID       uuid.UUID `json:"grant_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &approved) != nil {
		t.Fatal("invalid approval")
	}
	callback, err := url.Parse(approved.Redirect)
	if err != nil || callback.Host != "127.0.0.1:4999" || callback.Query().Get("state") != "correlation" || callback.Query().Get("iss") != f.u.cfg.IssuerURL {
		t.Fatal("callback binding lost", err)
	}
	g, err := f.st.GetCredentialGrant(t.Context(), f.owner.ID, approved.ID)
	if err != nil || g.ExpiresAt.After(time.Now().Add(time.Hour)) || g.ClientBinding == nil || g.ClientBinding.Version != 2 {
		t.Fatal("grant lifetime/snapshot", err)
	}
	exchange := func(q url.Values) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/oauth/credentials/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.u.token(w, r)
		return w
	}
	q := url.Values{"grant_type": {"authorization_code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:4999/callback"}, "code": {callback.Query().Get("code")}, "code_verifier": {strings.Repeat("A", 43)}, "resource": {"https://workspace.example.test/"}}
	w = exchange(q)
	if w.Code != 200 {
		t.Fatal("code exchange", w.Code, w.Body)
	}
	var token struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &token) != nil || token.Access == "" || token.Refresh == "" {
		t.Fatal("token missing")
	}
	q = url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "refresh_token": {token.Refresh}, "resource": {"https://workspace.example.test/"}}
	if w = exchange(q); w.Code != 200 {
		t.Fatal("public refresh", w.Code, w.Body)
	}
	if w = exchange(q); w.Code != 400 {
		t.Fatal("refresh replay accepted", w.Code)
	}
	if _, err := f.st.FindCredentialSecret(t.Context(), hashValue(token.Access), store.SecretAccess, 1); err == nil {
		t.Fatal("refresh replay did not revoke family")
	}
}
func TestPublicOAuthDenialIsTerminalAndAuditedPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	id, browser := f.start(t)
	db, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(context.Background()) }()
	if _, err := db.Exec(t.Context(), `ALTER TABLE csar_audit_outbox ADD CONSTRAINT deny_audit_fail CHECK(convert_from(payload,'UTF8')::jsonb->>'action'<>'credentials.authorization.deny') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"request_id": id}
	w := f.mutate(t, "/oauth/credentials/deny", input, browser, f.u.denyAuthorization)
	if w.Code != 503 {
		t.Fatal("audit failure did not fail closed", w.Code, w.Body)
	}
	if _, err := f.st.CredentialAuthorization(t.Context(), id, hashValue(browser.Value)); err != nil {
		t.Fatal("unaudited denial consumed request", err)
	}
	if _, err := db.Exec(t.Context(), `ALTER TABLE csar_audit_outbox DROP CONSTRAINT deny_audit_fail`); err != nil {
		t.Fatal(err)
	}
	w = f.mutate(t, "/oauth/credentials/deny", input, browser, f.u.denyAuthorization)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var out struct {
		Redirect string `json:"redirect"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal("invalid denial")
	}
	callback, err := url.Parse(out.Redirect)
	if err != nil || callback.Host != "127.0.0.1:4999" || callback.Query().Get("error") != "access_denied" || callback.Query().Get("state") != "correlation" || callback.Query().Has("code") {
		t.Fatal("denial callback corrupted")
	}
	if _, err := f.st.CredentialAuthorization(t.Context(), id, hashValue(browser.Value)); err == nil {
		t.Fatal("denied request remained approvable")
	}
	if w = f.mutate(t, "/oauth/credentials/deny", input, browser, f.u.denyAuthorization); w.Code != 400 {
		t.Fatal("denial replay accepted", w.Code)
	}
	var events, grants int
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM csar_audit_outbox WHERE convert_from(payload,'UTF8')::jsonb->>'action'='credentials.authorization.deny'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("missing denial audit", err, events)
	}
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM credential_grants`).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("denial created credential authority", err)
	}
}
func TestPublicOAuthDCRSharesProtectedAdmissionPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	register := func() *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/oauth/credentials/register", strings.NewReader(`{"client_name":"Registered app","redirect_uris":["http://127.0.0.1:4000/callback"],"token_endpoint_auth_method":"none"}`))
		r.Header.Set("Content-Type", "application/json")
		r.TLS = f.tls
		w := httptest.NewRecorder()
		f.u.publicIngress(f.u.clients.registerClient)(w, r)
		return w
	}
	first := register()
	if first.Code != 201 {
		t.Fatal(first.Code, first.Body)
	}
	var out store.OAuthClient
	if json.Unmarshal(first.Body.Bytes(), &out) != nil || !strings.HasPrefix(out.ClientID, "dcr_") {
		t.Fatal("DCR missing")
	}
	for range 49 {
		if w := register(); w.Code != 201 {
			t.Fatal("admission too early", w.Code)
		}
	}
	// Same socket peer gets the existing half of100/hour, even through an alias.
	if w := register(); w.Code != 429 {
		t.Fatal("registration quota reset", w.Code, w.Body)
	}
	for _, key := range mustRedisKeys(t, f.cache) {
		if !strings.HasPrefix(key, "authn:mcp:") {
			t.Fatal("new quota namespace", key)
		}
	}
}
func mustRedisKeys(t *testing.T, c *redis.Client) []string {
	t.Helper()
	keys, err := c.Keys(t.Context(), "*").Result()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestPublicOAuthCannotSubstituteProfileOrExpandRequestPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	id, browser := f.start(t)
	other := f.u.cfg.Profiles[0]
	other.ID = "other"
	other.Audience = "https://other.example.test"
	f.u.cfg.Profiles = append(f.u.cfg.Profiles, other)
	f.u.cfg.PublicOAuth.Profiles = append(f.u.cfg.PublicOAuth.Profiles, authnconfig.CredentialOAuthProfile{ProfileID: "other"})
	base := map[string]any{"request_id": id, "profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "current_and_future"}, "label": "Public", "caller_kind": "agent", "ttl_seconds": 60}
	for _, mode := range []string{"profile", "scope"} {
		t.Run(mode, func(t *testing.T) {
			in := map[string]any{}
			for k, v := range base {
				in[k] = v
			}
			if mode == "profile" {
				in["profile_id"] = "other"
			} else {
				in["scopes"] = []string{"documents:read"}
			}
			w := f.mutate(t, "/oauth/credentials/approve", in, browser, f.u.approveAuthorization)
			if w.Code != 400 {
				t.Fatal("request authority widened", w.Code, w.Body)
			}
		})
	}
	// A short explicit grant also bounds its authorization code; it must not fail
	// because the normal five-minute code lifetime exceeds a one-minute grant.
	w := f.mutate(t, "/oauth/credentials/approve", base, browser, f.u.approveAuthorization)
	if w.Code != 200 {
		t.Fatal("short grant failed", w.Code, w.Body)
	}
}
func TestPublicOAuthRejectsAmbiguousAuthorizeInputPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	for _, query := range []string{"response_type=code&resource=https%3A%2F%2Funknown.test", "response_type=code&response_type=code", "response_type=code&resource=https%3A%2F%2Fworkspace.example.test&scope=facts%3Aread&scope=documents%3Aread", "response_type=code&client_secret=forbidden"} {
		r := httptest.NewRequest("GET", "/oauth/credentials/authorize?"+query, nil)
		r.TLS = f.tls
		w := httptest.NewRecorder()
		f.u.publicAuthorize(w, r)
		if w.Code != 400 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
			t.Fatal("ambiguous input created browser authority", w.Code)
		}
	}
}

func TestPublicOAuthStartupIsAtomicAndOwnsPolicyPG(t *testing.T) {
	f := newPublicCredentialFixture(t)
	f.u.h.Config().Credentials = &f.u.cfg
	listener := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	mux := http.NewServeMux()
	if err := f.u.h.RegisterCredentials(mux, listener, f.u.decisions); err == nil {
		t.Fatal("public admission activated without dependencies")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/credentials/metadata", nil))
	if w.Code != 404 {
		t.Fatal("partial public startup installed routes")
	}
	if err := f.u.h.RegisterCredentials(mux, listener, f.u.decisions, PublicOAuthDependencies{Redis: f.cache, HTTPClient: f.u.clients.http}); err != nil {
		t.Fatal(err)
	}
	f.u.cfg.PublicOAuth.AuthorizationEndpoint = "https://mutated.example.test/authorize"
	r := httptest.NewRequest("GET", "/oauth/credentials/metadata", nil)
	r.TLS = f.tls
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "mutated") || !strings.Contains(w.Body.String(), "client_id_metadata_document_supported") {
		t.Fatal("mutable startup policy", w.Code, w.Body)
	}
	r = httptest.NewRequest("GET", "/oauth/credentials/metadata", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("feature ingress bypassed", w.Code)
	}
}
