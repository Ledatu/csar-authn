package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/postgres"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/stsclient"
	"golang.org/x/oauth2"
)

type credentialRoundTrip func(*http.Request) (*http.Response, error)

func (f credentialRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type credentialFixture struct {
	databaseURL string
	u           *credentialIssuer
	st          *postgres.Store
	owner       *store.User
	cookie      *http.Cookie
	tls         *tls.ConnectionState
	deny, fail  atomic.Bool
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable localhost PostgreSQL fixture not configured")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.Host != "127.0.0.1" && cfg.Host != "localhost") || cfg.Database != "csar_audit_test" || len(cfg.Fallbacks) > 0 {
		t.Fatal("only isolated localhost csar_audit_test accepted")
	}
	admin, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	database := "csar_credentials_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	ident := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+ident); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	databaseURL, err := url.Parse(dsn)
	if err != nil || (databaseURL.Scheme != "postgres" && databaseURL.Scheme != "postgresql") {
		t.Fatal("fixture requires a PostgreSQL URL")
	}
	databaseURL.Path = "/" + database
	st, err := postgres.New(t.Context(), databaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
		_, err := admin.Exec(context.Background(), "DROP DATABASE "+ident)
		if err != nil {
			t.Error(err)
		}
		if err := admin.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnableAuditOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	owner, err := st.CreateUser(t.Context(), &store.User{DisplayName: "generic owner"})
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newSessionsHandler(t, nil)
	h.store = st
	h.sessMgr = session.NewSessionManager(st, slog.Default(), time.Hour, time.Hour, time.Minute)
	sess, err := h.sessMgr.Create(t.Context(), owner.ID, "fixture", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Use real x509 verification for the feature-specific chain, not a forged CN.
	rootServer := httptest.NewTLSServer(nil)
	key := rootServer.TLS.Certificates[0].PrivateKey.(crypto.Signer)
	rootServer.Close()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(907), Subject: pkix.Name{CommonName: "dedicated credential fixture CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(908), Subject: pkix.Name{CommonName: "credentials-router"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	profile := authnconfig.CredentialProfile{ID: "workspace", Revision: 1, Audience: "https://workspace.example.test", Scopes: []authnconfig.CredentialScope{{Scope: "facts:read", DecisionProfile: "facts-reader"}, {Scope: "documents:read", DecisionProfile: "document-reader"}}, Namespaces: []string{"workspace", "documents"}, SelectionModes: []authntokens.SelectionMode{authntokens.Selected, authntokens.CurrentAndFuture}, AccessTTL: authnconfig.NewDuration(time.Hour), GrantTTL: authnconfig.NewDuration(24 * time.Hour), ProofTTL: authnconfig.NewDuration(time.Minute), TrustPolicy: "ingress"}
	policy := authnconfig.CredentialConfig{Version: 1, Enabled: true, IssuerURL: "https://id.example.test", ConsentURL: "https://console.example.test/consent", MutationOrigins: []string{"https://console.example.test"}, ConsentCookieName: "__Host-credential-consent", Profiles: []authnconfig.CredentialProfile{profile}, TrustPolicies: []authnconfig.CredentialTrustPolicy{{ID: "ingress", CAFile: file, PeerCN: "credentials-router"}}, Receivers: []authnconfig.CredentialReceiver{{Subject: "svc:resource-owner", Profiles: []string{"workspace"}, Operations: []string{"inspect", "evaluate"}, TrustPolicy: "ingress"}}}
	h.cfg.Load().AuditOutboxEnabled = true
	h.cfg.Load().Cookie.Secure = true
	h.cfg.Load().Credentials = &policy
	f := &credentialFixture{databaseURL: databaseURL.String(), st: st, owner: owner, cookie: &http.Cookie{Name: "session", Value: sess.ID}, tls: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: chains}}
	client := &stsclient.RouterClient{BaseURL: "https://router.example.test", Client: &http.Client{Transport: credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
		var in struct {
			Version   int                       `json:"version"`
			Profile   string                    `json:"profile"`
			Audience  string                    `json:"audience"`
			Subject   string                    `json:"subject"`
			Mode      string                    `json:"subject_mode"`
			Resources []authntokens.ResourceRef `json:"resources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return nil, err
		}
		if in.Subject != owner.ID.String() || in.Mode != "background" || r.URL.Path != "/svc/decisions/check" {
			t.Error("caller supplied policy/subject bypass")
		}
		results := make([]credentialDecision, len(in.Resources))
		for i, ref := range in.Resources {
			results[i] = credentialDecision{Resource: ref, Allowed: !f.deny.Load()}
			if results[i].Allowed {
				results[i].Scope = &authntokens.ScopeRef{Type: "tenant", ID: ref.Namespace + ":" + ref.ID}
			}
		}
		body, _ := json.Marshal(map[string]any{"version": 1, "profile": in.Profile, "audience": in.Audience, "subject": in.Subject, "results": results})
		status := 200
		if f.fail.Load() {
			status = 503
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	f.u = &credentialIssuer{h: h, cfg: policy, store: st, decisions: client, trust: map[string]credentialTrust{"ingress": {ca: root, peer: "credentials-router"}}}
	return f
}
func (f *credentialFixture) send(t *testing.T, method, path string, body any, handler http.HandlerFunc, owner bool) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.TLS = f.tls
	r.Header.Set("Origin", "https://console.example.test")
	if owner {
		r.AddCookie(f.cookie)
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}
func (f *credentialFixture) issue(t *testing.T) (string, uuid.UUID) {
	t.Helper()
	w := f.send(t, "POST", "/auth/me/credentials", map[string]any{"profile_id": "workspace", "scopes": []string{"facts:read", "documents:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "selected", "resources": []authntokens.ResourceRef{{Namespace: "workspace", ID: "north-branch"}}}, "label": "test", "caller_kind": "agent"}, f.u.create, true)
	if w.Code != 201 {
		t.Fatal("issuance", w.Code, w.Body.String())
	}
	var out struct {
		Token string    `json:"token"`
		ID    uuid.UUID `json:"id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Token == "" {
		t.Fatal("missing one-time token")
	}
	return out.Token, out.ID
}
func TestGenericIssuerSessionAndRevisionPolicyPG(t *testing.T) {
	f := newCredentialFixture(t)
	raw, gid := f.issue(t)
	state, err := f.st.FindCredentialSecret(t.Context(), hashValue(raw), store.SecretAccess, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := &f.u.cfg.Profiles[0]
	p.Revision = 2
	p.AcceptedGrantRevisions = []uint64{1, 2}
	p.Scopes = p.Scopes[:1]
	p.Namespaces = append(p.Namespaces, "expanded")
	_, _, effective, err := f.u.state(t.Context(), raw, store.SecretAccess)
	if err != nil || effective.ProfileRevision != 1 || len(effective.Scopes) != 1 || len(effective.Namespaces) != 1 {
		t.Fatal("revision intersection widened or rewrote consent", err)
	}
	stored, err := f.st.GetCredentialGrant(t.Context(), f.owner.ID, gid)
	if err != nil || len(stored.Constraints.Scopes) != 2 || stored.Constraints.ProfileRevision != 1 {
		t.Fatal("stored grant mutated", err)
	}
	p.AcceptedGrantRevisions = nil
	if _, _, _, err := f.u.state(t.Context(), raw, store.SecretAccess); err == nil {
		t.Fatal("unlisted revision accepted")
	}
	p.AcceptedGrantRevisions = []uint64{1, 2}
	p.Audience += "/changed"
	if _, _, _, err := f.u.state(t.Context(), raw, store.SecretAccess); err == nil {
		t.Fatal("audience reinterpretation accepted")
	}
	// Classified caller comes from the actual caller row, not a transport name.
	if credentialIdentity(&state).CallerKind != caller.Agent {
		t.Fatal("caller attribution lost")
	}
	for _, tc := range []struct {
		origin string
		bearer bool
		cookie bool
		want   int
	}{{"https://evil.test", false, true, 403}, {"https://console.example.test", true, true, 401}, {"https://console.example.test", false, false, 401}} {
		req := httptest.NewRequest("POST", "/auth/me/credentials", strings.NewReader(`{}`))
		req.Header.Set("Origin", tc.origin)
		if tc.cookie {
			req.AddCookie(f.cookie)
		}
		if tc.bearer {
			req.Header.Set("Authorization", "Bearer forged")
		}
		w := httptest.NewRecorder()
		f.u.create(w, req)
		if w.Code != tc.want {
			t.Fatal("owner guard", w.Code)
		}
	}
}
func TestGenericIssuerProofPurposeNamespaceAndReplayPG(t *testing.T) {
	f := newCredentialFixture(t)
	raw, _ := f.issue(t)
	request := authntokens.DelegationRequestV2{Version: 2, Token: raw, Purpose: authntokens.GrantExchange, ProfileID: "workspace", Audience: f.u.cfg.Profiles[0].Audience, Scope: "facts:read", Namespace: "workspace"}
	w := f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out authntokens.DelegationResultV2
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.ValidateFor(&request, time.Now()) != nil {
		t.Fatal("v2 exchange invalid", w.Body.String())
	}
	proof := out.DelegatedToken
	request.Purpose = authntokens.GrantDiscovery
	request.Token = proof
	request.Scope = "documents:read"
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("proof changed consented scope")
	}
	request.Scope = "facts:read"
	request.Namespace = "documents"
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("proof changed namespace")
	}
	request.Namespace = "workspace"
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Active {
		t.Fatal("discovery rejected", w.Body.String())
	}
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("proof replay accepted")
	}
	mutated := strings.Replace(proof, strings.Split(proof, ".")[1], base64.RawURLEncoding.EncodeToString([]byte(`{"namespace":"workspace","scope":"documents:read"}`)), 1)
	request.Token = mutated
	request.Scope = "documents:read"
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("proof hash did not bind metadata")
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	f.u.introspect(w, r)
	if w.Code != 403 {
		t.Fatal("missing configured TLS accepted")
	}
}
func TestGenericOAuthConsentRotationAndReplayPG(t *testing.T) {
	f := newCredentialFixture(t)
	client := store.MCPClient{ClientID: "https://client.example.test/id", ClientName: "Client", RedirectURIs: []string{"https://client.example.test/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, AuthMethod: "none"}
	if _, err := f.st.RegisterMCPClient(t.Context(), client, strings.Repeat("a", 64), 4096); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("A", 43)
	in := map[string]any{"profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "client_id": client.ClientID, "redirect_uri": client.RedirectURIs[0], "code_challenge_method": "S256", "code_challenge": oauth2.S256ChallengeFromVerifier(verifier), "state": "correlation"}
	w := f.send(t, "POST", "/oauth/credentials/authorize", in, f.u.beginAuthorization, false)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var started struct {
		ID string `json:"request_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &started) != nil || started.ID == "" {
		t.Fatal("request missing")
	}
	var browser *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == f.u.cfg.ConsentCookieName {
			browser = c
		}
	}
	if browser == nil || !browser.Secure || !browser.HttpOnly {
		t.Fatal("browser binding absent")
	}
	approve := map[string]any{"request_id": started.ID, "profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "selected", "resources": []authntokens.ResourceRef{{Namespace: "workspace", ID: "north-branch"}}}, "label": "OAuth", "caller_kind": "application"}
	data, _ := json.Marshal(approve)
	r := httptest.NewRequest("POST", "/oauth/credentials/approve", bytes.NewReader(data))
	r.Header.Set("Origin", "https://console.example.test")
	r.AddCookie(f.cookie)
	r.AddCookie(browser)
	w = httptest.NewRecorder()
	f.u.approveAuthorization(w, r)
	if w.Code != 200 {
		t.Fatal("approval", w.Code, w.Body.String())
	}
	var approved struct {
		Redirect string    `json:"redirect"`
		GrantID  uuid.UUID `json:"grant_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &approved) != nil {
		t.Fatal("redirect missing")
	}
	callback, err := url.Parse(approved.Redirect)
	if err != nil || callback.Query().Get("state") != "correlation" {
		t.Fatal("callback binding")
	}
	exchange := func(q url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/oauth/credentials/token", strings.NewReader(q.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(gatewayctx.NewContext(req.Context(), &gatewayctx.Identity{Subject: "forged", Caller: &caller.Identity{Version: 999}}))
		w := httptest.NewRecorder()
		f.u.token(w, req)
		return w
	}
	q := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ClientID}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}, "code": {callback.Query().Get("code")}}
	w = exchange(q)
	if w.Code != 200 {
		t.Fatal("code", w.Code, w.Body.String())
	}
	var tokens struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.Refresh == "" {
		t.Fatal("tokens missing")
	}
	if w = exchange(q); w.Code != 400 {
		t.Fatal("code replay")
	}
	q = url.Values{"grant_type": {"refresh_token"}, "client_id": {client.ClientID}, "refresh_token": {tokens.Refresh}}
	w = exchange(q)
	if w.Code != 200 {
		t.Fatal("rotation", w.Code, w.Body.String())
	}
	if _, err := f.st.FindCredentialSecret(t.Context(), hashValue(tokens.Access), store.SecretAccess, 1); err == nil {
		t.Fatal("old access still active")
	}
	f.u.cfg.Profiles[0].Revision = 2 // temporarily incompatible with the original grant
	w = exchange(q)
	if w.Code != 400 {
		t.Fatal("refresh replay")
	}
	f.u.cfg.Profiles[0].Revision = 1 // restoring policy cannot undo replay revocation

	if _, err := f.st.GetCredentialGrant(t.Context(), f.owner.ID, approved.GrantID); err == nil {
		t.Fatal("replay family not revoked")
	}
	auditConn, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditConn.Close(context.Background()) }()
	rows, err := auditConn.Query(t.Context(), `SELECT payload FROM csar_audit_outbox WHERE convert_from(payload,'UTF8')::jsonb->>'action' IN ('credentials.secret.exchange','credentials.refresh.replay')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var event audit.Event
		if json.Unmarshal(payload, &event) != nil || event.Caller == nil || event.Caller.OwnerSubject != f.owner.ID.String() || event.Caller.CredentialKind != caller.OAuthAccess || event.OriginCaller != nil {
			t.Fatal("public token exchange inherited unverified context")
		}
		seen++
	}
	if rows.Err() != nil || seen != 3 {
		t.Fatal("mutation audit coverage", seen, rows.Err())
	}

}

// Bind test service requests to a verified original credential, never body fields.
func genericServiceContext(t *testing.T, r *http.Request, s *store.CredentialState) {
	r.Header.Set(gatewayctx.HeaderSubject, "svc:resource-owner")
	service := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "svc:resource-owner", EffectiveSubject: "svc:resource-owner", CredentialKind: caller.STS, Assurance: caller.Verified}
	if err := gatewayctx.SetCaller(r.Header, service); err != nil {
		t.Fatal(err)
	}
	if err := gatewayctx.SetOrigin(r.Header, &gatewayctx.Origin{Account: &authntokens.AccountBinding{Kind: "credential", ProfileID: s.Grant.Constraints.ProfileID, ProfileRevision: s.Grant.Constraints.ProfileRevision, Audience: s.Grant.Constraints.Audience}, OperationID: uuid.NewString(), Caller: credentialIdentity(s), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func TestGenericServiceCapabilityAndCurrentResourceAuthorityPG(t *testing.T) {
	f := newCredentialFixture(t)
	raw, gid := f.issue(t)
	state, err := f.st.FindCredentialSecret(t.Context(), hashValue(raw), store.SecretAccess, 1)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"version": 2, "profile_id": "workspace", "owner_id": f.owner.ID, "grant_id": gid, "scope": "facts:read", "resources": []authntokens.ResourceRef{{Namespace: "workspace", ID: "north-branch"}}, "issue_proof": true}
	send := func(in any, withContext bool, trust bool, fn http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(in)
		r := httptest.NewRequest("POST", "/svc/credentials/evaluate", bytes.NewReader(b))
		if trust {
			r.TLS = f.tls
		}
		if withContext {
			genericServiceContext(t, r, &state)
		}
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	for _, tc := range []struct{ context, trust bool }{{false, true}, {true, false}} {
		if w := send(input, tc.context, tc.trust, f.u.evaluate); w.Code != 403 {
			t.Fatal("service/origin/CA required", w.Code)
		}
	}
	w := send(input, true, true, f.u.evaluate)
	if w.Code != 200 {
		t.Fatal("evaluate", w.Code, w.Body.String())
	}
	var evaluated struct {
		Proof   string               `json:"proof"`
		Results []credentialDecision `json:"results"`
	}
	if json.Unmarshal(w.Body.Bytes(), &evaluated) != nil || evaluated.Proof == "" || len(evaluated.Results) != 1 || !evaluated.Results[0].Allowed {
		t.Fatal("allowed result/proof absent", w.Body.String())
	}
	ref := authntokens.ResourceRef{Namespace: "workspace", ID: "north-branch"}
	request := authntokens.DelegationRequestV2{Version: 2, Token: evaluated.Proof, Purpose: authntokens.GrantResource, ProfileID: "workspace", Audience: f.u.cfg.Profiles[0].Audience, Scope: "facts:read", Namespace: "workspace", Resource: &ref}
	f.deny.Store(true)
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("resource used stale authority")
	}
	w = send(input, true, true, f.u.evaluate)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatal("current deny was not preserved")
	}
	f.deny.Store(false)
	f.fail.Store(true)
	w = send(input, true, true, f.u.evaluate)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"results"`) {
		t.Fatal("authorization failure produced partial allow")
	}
	f.fail.Store(false)
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	var result authntokens.DelegationResultV2
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ValidateFor(&request, time.Now()) != nil {
		t.Fatal("live resource proof rejected", w.Code, w.Body.String())
	}
	w = f.send(t, "POST", "/internal/credentials/v2/introspect", request, f.u.introspect, false)
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("resource proof replay")
	}
	input["owner_id"] = uuid.New()
	if w = send(input, true, true, f.u.evaluate); w.Code != 403 {
		t.Fatal("substituted owner accepted")
	}
	input["owner_id"] = f.owner.ID
	f.u.cfg.Receivers[0].Operations = []string{"inspect"}
	if w = send(input, true, true, f.u.evaluate); w.Code != 403 {
		t.Fatal("inspect capability inherited evaluate")
	}
}

func TestGenericIssuerTwoApplicationPoliciesPG(t *testing.T) {
	f := newCredentialFixture(t)
	for _, app := range []struct{ profile, namespace, scope, id string }{{"aurum-reports", "wildberries", "analytics:read", uuid.NewString()}, {"workspace-reports", "workspace", "facts:read", "north-branch"}} {
		p := &f.u.cfg.Profiles[0]
		p.ID = app.profile
		p.Audience = "https://" + app.profile + ".example.test"
		p.Scopes = []authnconfig.CredentialScope{{Scope: app.scope, DecisionProfile: "reader"}}
		p.Namespaces = []string{app.namespace}
		body := map[string]any{"profile_id": app.profile, "scopes": []string{app.scope}, "namespaces": []string{app.namespace}, "selection": map[string]any{"mode": "selected", "resources": []authntokens.ResourceRef{{Namespace: app.namespace, ID: app.id}}}, "label": "Client"}
		w := f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true)
		if w.Code != 201 {
			t.Fatal("generic app rejected", app.profile, w.Code, w.Body.String())
		}
		var out struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("invalid output")
		}
		_, _, effective, err := f.u.state(t.Context(), out.Token, store.SecretAccess)
		if err != nil || effective.ProfileID != app.profile || effective.Selection.Resources[0].ID != app.id {
			t.Fatal("business identity was reinterpreted", err)
		}
		body["kind"] = "oauth_access"
		if w = f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 400 {
			t.Fatal("manual issuance bypassed its cap using a family label")
		}
	}
}

func TestGenericRegistrationIsAtomicAndOwnsStartupConfigPG(t *testing.T) {
	f := newCredentialFixture(t)
	h := f.u.h
	mux := http.NewServeMux()
	cfg := h.Config()
	cfg.Credentials.Enabled = false
	if err := h.RegisterCredentials(mux, nil, nil); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/auth/me/credentials", nil))
	if w.Code != 404 {
		t.Fatal("disabled issuer registered routes")
	}
	cfg.Credentials.Enabled = true
	if err := h.RegisterCredentials(mux, nil, f.u.decisions); err == nil {
		t.Fatal("unverified listener activated issuer")
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/auth/me/credentials", nil))
	if w.Code != 404 {
		t.Fatal("partial startup installed routes")
	}
	listener := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	if err := h.RegisterCredentials(mux, listener, f.u.decisions); err != nil {
		t.Fatal(err)
	}
	// Caller mutation of the original config cannot broaden registered policy.
	cfg.Credentials.MutationOrigins[0] = "https://evil.example.test"
	req := httptest.NewRequest("POST", "/auth/me/credentials", strings.NewReader(`{}`))
	req.AddCookie(f.cookie)
	req.Header.Set("Origin", "https://evil.example.test")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("running issuer inherited a mutable startup origin", w.Code)
	}
}

func TestManualConnectionProfileLifetimeAndSharedCapacityPG(t *testing.T) {
	f := newCredentialFixture(t)
	p := &f.u.cfg.Profiles[0]
	p.GrantTTL = authnconfig.NewDuration(168 * time.Hour)
	p.ManualIssuance = &authnconfig.CredentialManualIssuance{Family: "connection", MaxTTL: authnconfig.NewDuration(168 * time.Hour)}
	body := map[string]any{"profile_id": p.ID, "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "current_and_future"}, "ttl_seconds": int64(168 * 3600)}
	for _, ttl := range []int64{0, -1, 3599, 168*3600 + 1, 1<<63 - 1} {
		body["ttl_seconds"] = ttl
		if w := f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 400 {
			t.Fatal("invalid manual lifetime admitted", ttl, w.Code)
		}
	}
	body["ttl_seconds"] = int64(168 * 3600)
	body["kind"] = "api_key"
	if w := f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 400 {
		t.Fatal("body selected family", w.Code)
	}
	delete(body, "kind")
	before := time.Now()
	w := f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out struct {
		Token     string    `json:"token"`
		ID        uuid.UUID `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	state, _, _, err := f.u.state(t.Context(), out.Token, store.SecretAccess)
	if err != nil || state.Grant.Kind != caller.OAuthAccess || state.Grant.ClientBinding != nil || out.ExpiresAt.Before(before.Add(168*time.Hour)) || !state.Grant.ExpiresAt.Equal(state.Secret.ExpiresAt) {
		t.Fatal("manual policy/deadline lost", err)
	}
	// A connection family is accounting, never an OAuth client/refresh capability.
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"invented"}, "refresh_token": {out.Token}}
	r := httptest.NewRequest("POST", "/oauth/credentials/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denied := httptest.NewRecorder()
	f.u.token(denied, r)
	if denied.Code != 400 {
		t.Fatal("manual connection gained refresh", denied.Code)
	}
	// The same owner cap includes one old-format manual connection and all generic
	// manual grants. Reusing its caller cannot create a second cap or registry entry.
	_, err = f.st.CreateManualMCP(t.Context(), store.MCPManualToken{OwnerID: f.owner.ID, CallerID: &state.Grant.CallerID, Selection: store.MCPSelection{AllCampaigns: true}, AccessHash: hashValue("legacy-manual-fixture"), Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	body["caller_id"] = state.Grant.CallerID
	body["ttl_seconds"] = int64(3600)
	for i := 2; i < store.CredentialOAuthLimit; i++ {
		if w = f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 201 {
			t.Fatal("connection capacity narrowed", i, w.Code, w.Body.String())
		}
	}
	if w = f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 409 {
		t.Fatal("aggregate connection cap bypassed", w.Code)
	}
	// Personal API capacity remains separate and at five, selected by server policy.
	p.ManualIssuance = nil
	delete(body, "ttl_seconds")
	for range store.CredentialAPIKeyLimit {
		if w = f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 201 {
			t.Fatal("API cap incorrectly shares connection slots", w.Code)
		}
	}
	if w = f.send(t, "POST", "/auth/me/credentials", body, f.u.create, true); w.Code != 409 {
		t.Fatal("personal key cap bypassed", w.Code)
	}
}

func TestDirectResourceAccessIsReusableCurrentAndAuditedPG(t *testing.T) {
	f := newCredentialFixture(t)
	raw, gid := f.issue(t)
	ref := authntokens.ResourceRef{Namespace: "workspace", ID: "north-branch"}
	in := authntokens.DelegationRequestV2{Version: 2, Token: raw, Purpose: authntokens.AccessResource, ProfileID: "workspace", Audience: f.u.cfg.Profiles[0].Audience, Scope: "facts:read", Namespace: "workspace", Resource: &ref}
	for range 2 {
		w := f.send(t, "POST", "/internal/credentials/v2/introspect", in, f.u.introspect, false)
		var out authntokens.DelegationResultV2
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.ValidateFor(&in, time.Now()) != nil || out.Identity.CredentialKind != caller.APIKey || out.DelegatedToken != "" {
			t.Fatal("direct use not bound/reusable", w.Code, w.Body.String())
		}
	}
	state, err := f.st.FindCredentialSecret(t.Context(), hashValue(raw), store.SecretAccess, 1)
	if err != nil || state.Secret.SpentAt != nil {
		t.Fatal("reusable access consumed", err)
	}
	inspect := map[string]any{"version": 2, "profile_id": "workspace", "owner_id": f.owner.ID, "grant_id": gid, "scope": "facts:read"}
	for _, mutate := range []func(*gatewayctx.Origin){func(o *gatewayctx.Origin) { o.Account = nil }, func(o *gatewayctx.Origin) { o.Account.ProfileID = "foreign" }, func(o *gatewayctx.Origin) { o.Account.Audience = "https://foreign.test" }, func(o *gatewayctx.Origin) { o.Account.ProfileRevision++ }} {
		body, _ := json.Marshal(inspect)
		r := httptest.NewRequest("POST", "/svc/credentials/inspect", bytes.NewReader(body))
		r.TLS = f.tls
		genericServiceContext(t, r, &state)
		origin, err := gatewayctx.OriginFromHeaders(r.Header)
		if err != nil {
			t.Fatal(err)
		}
		mutate(origin)
		if err := gatewayctx.SetOrigin(r.Header, origin); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		f.u.inspect(w, r)
		if w.Code != 403 {
			t.Fatal("foreign account binding accepted", w.Code)
		}
	}
	f.deny.Store(true)
	if w := f.send(t, "POST", "/internal/credentials/v2/introspect", in, f.u.introspect, false); strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("stale direct permission used")
	}
	f.deny.Store(false)
	in.Purpose = authntokens.GrantResource
	if w := f.send(t, "POST", "/internal/credentials/v2/introspect", in, f.u.introspect, false); strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("access fell back into proof mode")
	}
	in.Purpose = authntokens.AccessResource
	if err := f.st.RevokeCredentialGrant(t.Context(), f.owner.ID, gid); err != nil {
		t.Fatal(err)
	}
	if w := f.send(t, "POST", "/internal/credentials/v2/introspect", in, f.u.introspect, false); strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("revoked direct access used")
	}
}
