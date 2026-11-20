package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/postgres"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"golang.org/x/oauth2"
)

type mcpFixtureStore struct {
	store.Store
	store.MCPGrantStore
}

// Uses an isolated localhost PostgreSQL fixture. Login and the Authz decision use
// the normal handler test doubles; authorization codes, grants and delegation are real.
func TestSellerMCPGrantLifecycle(t *testing.T) {
	dsn := os.Getenv("MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set MCP_TEST_DATABASE_URL to run PostgreSQL grant lifecycle")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/csar_mcp_test" {
		t.Fatal("expected local csar_mcp_test fixture")
	}
	db, err := postgres.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool().Exec(t.Context(), "INSERT INTO users(id) VALUES($1) ON CONFLICT DO NOTHING", testUserID); err != nil {
		t.Fatal(err)
	}
	th, _, session := apiKeyScopeHarness(t)
	th.handler.store = mcpFixtureStore{th.store, db}
	const client = "analytics-pilot"
	const redirect = "http://127.0.0.1:8765/callback"
	seller := uuid.NewString()
	var allowed atomic.Bool
	th.mock.checkAccessFn = func(_ context.Context, r *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		return &pb.CheckAccessResponse{Allowed: allowed.Load() && r.Subject == testUserID.String() && r.ScopeId == "wildberries:"+seller && r.Action == "analytics.read"}, nil
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(nil)
	ca := server.Certificate()
	server.Close()
	caFile := filepath.Join(t.TempDir(), "router-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	listener := &tls.Config{MinVersion: tls.VersionTLS13, ClientCAs: x509.NewCertPool(), ClientAuth: tls.RequireAndVerifyClientCert}
	if err = th.handler.RegisterSellerMCP(mux, client, redirect, caFile, listener); err != nil {
		t.Fatal(err)
	}
	send := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	verifier := oauth2.GenerateVerifier()
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "scope": {store.APIKeyScopeAnalyticsRead}, "resource": {mcpResource}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}, "state": {"client-state"}}
	begin := send(httptest.NewRequest("GET", "/oauth/mcp/authorize?"+q.Encode(), nil))
	if begin.Code != 303 {
		t.Fatalf("authorize=%d", begin.Code)
	}
	dest, _ := url.Parse(begin.Header().Get("Location"))
	cookie := begin.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" {
		t.Fatal("consent binding cookie")
	}
	decision := "approve"
	decide := func(origin string, addBrowserCookie bool) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(map[string]string{"client_id": client, "decision": decision, "seller_id": seller, "request": dest.Query().Get("mcp_request")})
		r := httptest.NewRequest("POST", "/oauth/mcp/consent", strings.NewReader(string(payload)))
		r.AddCookie(session)
		r.Header.Set("Origin", origin)
		if addBrowserCookie {
			r.AddCookie(cookie)
		}
		return send(r)
	}
	if decide("https://seller.aurum-sky.net", true).Code != 403 {
		t.Fatal("consent without current permission")
	}
	allowed.Store(true)
	impersonated, err := th.handler.sessMgr.CreateImpersonated(t.Context(), testUserID, uuid.New(), "support", "test", "127.0.0.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ownerSession := session
	session = &http.Cookie{Name: session.Name, Value: impersonated.ID}
	if decide(sellerOrigin, true).Code != http.StatusForbidden {
		t.Fatal("impersonated session could approve consent")
	}
	session = ownerSession
	if decide("https://other.invalid", true).Code != 403 || decide("https://seller.aurum-sky.net", false).Code != 400 {
		t.Fatal("consent must bind origin and browser")
	}
	w := decide("https://seller.aurum-sky.net", true)
	if w.Code != 200 {
		t.Fatalf("approve=%d", w.Code)
	}
	var result struct{ Redirect string }
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(result.Redirect)
	if callback.Query().Get("state") != "client-state" || callback.Query().Get("iss") != mcpIssuer {
		t.Fatal("incorrect callback")
	}
	redeem := func(verifier, resource string) *httptest.ResponseRecorder {
		v := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {redirect}, "client_id": {client}, "resource": {resource}}
		r := httptest.NewRequest("POST", "/oauth/mcp/token", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return send(r)
	}
	if redeem(oauth2.GenerateVerifier(), mcpResource).Code != 400 || redeem(verifier, "https://other.invalid").Code != 400 {
		t.Fatal("PKCE and resource binding")
	}
	w = redeem(verifier, mcpResource+"/")
	if w.Code != 200 || redeem(verifier, mcpResource).Code != 400 {
		t.Fatal("code must redeem exactly once")
	}
	var access struct {
		Token string `json:"access_token"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	type response struct {
		Active bool
		Proof  string `json:"delegated_token"`
		Grant  string `json:"credential_id"`
		Seller string `json:"seller_id"`
	}
	intro := func(op, token string) response {
		body, _ := json.Marshal(map[string]string{"token": token})
		r := httptest.NewRequest("POST", "/internal/seller-mcp/"+op, strings.NewReader(string(body)))
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert, ca}}}
		w := send(r)
		var out response
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Errorf("introspection %s=%d", op, w.Code)
		}
		return out
	}
	first := intro("delegate", access.Token)
	if !first.Active || first.Seller != seller || first.Proof == access.Token || intro("consume", access.Token).Active || intro("delegate", first.Proof).Active {
		t.Fatal("resource isolation")
	}
	otherOwner := uuid.New()
	foreign, err := db.ListMCP(t.Context(), otherOwner)
	if err != nil || len(foreign) != 0 {
		t.Fatal("foreign owner grant list")
	}
	if err = db.RevokeMCP(t.Context(), otherOwner, uuid.MustParse(first.Grant)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign owner grant revocation")
	}
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if intro("consume", first.Proof).Active {
				successes.Add(1)
			}
		})
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("redeemed %d times", successes.Load())
	}
	outstanding := intro("delegate", access.Token)
	r := httptest.NewRequest("DELETE", "/oauth/mcp/connections/"+first.Grant, nil)
	r.AddCookie(session)
	r.Header.Set("Origin", "https://seller.aurum-sky.net")
	if send(r).Code != 204 || intro("consume", outstanding.Proof).Active || intro("delegate", access.Token).Active {
		t.Fatal("revocation did not close grant and outstanding delegations")
	}
	// A separate authorization transaction can be denied, and cannot be approved later.
	begin = send(httptest.NewRequest("GET", "/oauth/mcp/authorize?"+q.Encode(), nil))
	dest, _ = url.Parse(begin.Header().Get("Location"))
	cookie = begin.Result().Cookies()[0]
	decision = "deny"
	w = decide("https://seller.aurum-sky.net", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("deny response")
	}
	callback, _ = url.Parse(result.Redirect)
	if callback.Query().Get("error") != "access_denied" || callback.Query().Has("code") {
		t.Fatal("denied callback")
	}
	decision = "approve"
	if decide("https://seller.aurum-sky.net", true).Code != 400 {
		t.Fatal("denied transaction reused")
	}
}

func TestDelegationRequiresDedicatedRouterCA(t *testing.T) {
	ca := &x509.Certificate{Raw: []byte("dedicated")}
	other := &x509.Certificate{Raw: []byte("general")}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
	otherLeaf := &x509.Certificate{Subject: pkix.Name{CommonName: "csar-client"}}
	o := sellerOAuth{routerCA: ca}
	for _, chain := range [][]*x509.Certificate{nil, {leaf}, {leaf, other}, {otherLeaf, ca}} {
		if o.verifiedRouter(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}) {
			t.Fatal("accepted unexpected peer")
		}
	}
}
