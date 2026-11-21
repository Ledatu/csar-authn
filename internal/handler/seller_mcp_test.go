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
	"github.com/ledatu/csar-core/authntokens"
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
	for _, client := range append([]SellerMCPClient{{ClientID: "codex", RedirectURIs: []string{"http://127.0.0.1:48973/oauth/callback"}}}, testMCPClients()...) {
		for _, callback := range client.RedirectURIs {
			if client.AllowLoopbackPort && strings.HasPrefix(callback, "http://") {
				callback = "http://127.0.0.1:33418" + strings.TrimPrefix(callback, "http://127.0.0.1")
			}
			t.Run(client.ClientID+"/"+callback, func(t *testing.T) {
				testSellerMCPGrantLifecycle(t, client.ClientID, callback)
			})
		}
	}
}

func testSellerMCPGrantLifecycle(t *testing.T, client, redirect string) {
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
	if err = th.handler.RegisterSellerMCP(mux, "codex", "http://127.0.0.1:48973/oauth/callback", caFile, listener, testMCPClients()...); err != nil {
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
	consentClient := client
	selection := map[string]any{"seller_id": seller}
	decide := func(origin string, addBrowserCookie bool) *httptest.ResponseRecorder {
		fields := map[string]any{"client_id": consentClient, "decision": decision, "request": dest.Query().Get("mcp_request")}
		for k, v := range selection {
			fields[k] = v
		}
		payload, _ := json.Marshal(fields)
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
	otherClient, otherRedirect := "codex", "http://127.0.0.1:48973/oauth/callback"
	if client == "codex" {
		otherClient, otherRedirect = "cursor", "http://localhost:8787/callback"
	}
	consentClient = otherClient
	if decide(sellerOrigin, true).Code != 400 {
		t.Fatal("consent accepted another registered client")
	}
	consentClient = client
	originalBrowser := cookie.Value
	cookie.Value = randomToken()
	if decide(sellerOrigin, true).Code != 400 {
		t.Fatal("consent accepted another browser binding")
	}
	cookie.Value = originalBrowser
	w := decide("https://seller.aurum-sky.net", true)
	if w.Code != 200 {
		t.Fatalf("approve=%d", w.Code)
	}
	var result struct {
		Redirect string
		GrantID  string `json:"grant_id"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(result.Redirect)
	if _, err := uuid.Parse(result.GrantID); err != nil || callback.Query().Has("grant_id") {
		t.Fatal("expected a grant reference only in the seller response")
	}
	grants, err := db.ListMCP(t.Context(), testUserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if grant.ID.String() == result.GrantID {
			t.Fatal("unredeemed connection is listed as active")
		}
	}
	if callback.Query().Get("state") != "client-state" || callback.Query().Get("iss") != mcpIssuer {
		t.Fatal("incorrect callback")
	}
	tokenClient, tokenRedirect := client, redirect
	redeem := func(verifier, resource string) *httptest.ResponseRecorder {
		v := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {tokenRedirect}, "client_id": {tokenClient}, "resource": {resource}}
		r := httptest.NewRequest("POST", "/oauth/mcp/token", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return send(r)
	}
	if redeem(oauth2.GenerateVerifier(), mcpResource).Code != 400 || redeem(verifier, "https://other.invalid").Code != 400 {
		t.Fatal("PKCE and resource binding")
	}
	tokenClient, tokenRedirect = otherClient, otherRedirect
	if redeem(verifier, mcpResource).Code != 400 {
		t.Fatal("code redeemed by another registered client")
	}
	tokenClient, tokenRedirect = client, redirect
	for _, registered := range testMCPClients() {
		if registered.ClientID != client {
			continue
		}
		for _, alternative := range registered.RedirectURIs {
			if registered.AllowLoopbackPort && strings.HasPrefix(alternative, "http://") {
				alternative = "http://127.0.0.1:59001/"
			}
			if alternative == redirect {
				continue
			}
			tokenRedirect = alternative
			if redeem(verifier, mcpResource).Code != 400 {
				t.Fatal("code changed its exact registered callback")
			}
		}
	}
	tokenRedirect = redirect
	w = redeem(verifier, mcpResource+"/")
	if w.Code != 200 || redeem(verifier, mcpResource).Code != 400 {
		t.Fatal("code must redeem exactly once")
	}
	type tokenPair struct {
		Token   string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Seconds int    `json:"expires_in"`
	}
	var access tokenPair
	if err = json.Unmarshal(w.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	if access.Refresh != "" || access.Seconds != int(store.MCPAccessTTL.Seconds()) {
		t.Fatal("one-hour consent was silently extended")
	}
	refresh := func(raw string, override url.Values) (int, tokenPair) {
		t.Helper()
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {client}}
		for k, vals := range override {
			v[k] = vals
		}
		r := httptest.NewRequest("POST", "/oauth/mcp/token", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := send(r)
		var pair tokenPair
		if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil {
			t.Fatal(err)
		}
		return w.Code, pair
	}
	type response struct {
		Active bool
		Proof  string `json:"delegated_token"`
		Grant  string `json:"credential_id"`
		Seller string `json:"seller_id"`
	}
	intro := func(op, token string, sellers ...string) response {
		data := map[string]string{"token": token}
		if len(sellers) > 0 {
			data["seller_id"] = sellers[0]
		}
		body, _ := json.Marshal(data)
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
	portable := func(in authntokens.DelegationRequest) authntokens.DelegationResult {
		t.Helper()
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/internal/seller-mcp/v1/introspect", strings.NewReader(string(body)))
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert, ca}}}
		w := send(r)
		var result authntokens.DelegationResult
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("delegation endpoint status %d", w.Code)
		}
		return result
	}
	request := authntokens.DelegationRequest{Token: access.Token, Purpose: authntokens.GrantExchange, Audience: mcpResource, Scope: store.APIKeyScopeAnalyticsRead}
	wrong := request
	wrong.Audience = "https://projects.example"
	if portable(wrong).Active {
		t.Fatal("accepted foreign audience")
	}
	wrong = request
	wrong.Scope = "projects:read"
	if portable(wrong).Active {
		t.Fatal("accepted foreign scope")
	}
	exchanged := portable(request)
	if !exchanged.Active || exchanged.Tenant != "wildberries:"+seller || exchanged.Subject != testUserID.String() || exchanged.DelegatedToken == "" {
		t.Fatal("invalid single-resource exchange")
	}
	request.Purpose, request.Token = authntokens.GrantDiscovery, exchanged.DelegatedToken
	if got := portable(request); !got.Active || got.Tenant != "" || got.Purpose != request.Purpose || portable(request).Active {
		t.Fatal("discovery purpose or single use lost")
	}
	first := intro("delegate", access.Token)
	if first.Grant != result.GrantID {
		t.Fatal("receipt did not identify the redeemed connection")
	}
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
	result.GrantID = ""
	w = decide("https://seller.aurum-sky.net", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("deny response")
	}
	callback, _ = url.Parse(result.Redirect)
	if callback.Query().Get("error") != "access_denied" || callback.Query().Has("code") || result.GrantID != "" {
		t.Fatal("denied callback")
	}
	decision = "approve"
	if decide("https://seller.aurum-sky.net", true).Code != 400 {
		t.Fatal("denied transaction reused")
	}
	second, future := uuid.NewString(), uuid.NewString()
	th.mock.checkAccessFn = func(_ context.Context, r *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		return &pb.CheckAccessResponse{Allowed: r.Subject == testUserID.String() && (r.ScopeId == "wildberries:"+seller || r.ScopeId == "wildberries:"+second)}, nil
	}
	for _, all := range []bool{false, true} {
		begin = send(httptest.NewRequest("GET", "/oauth/mcp/authorize?"+q.Encode(), nil))
		dest, _ = url.Parse(begin.Header().Get("Location"))
		cookie = begin.Result().Cookies()[0]
		selection = map[string]any{"all_campaigns": true, "seller_ids": []string{seller}}
		if decide(sellerOrigin, true).Code != 400 {
			t.Fatal("accepted conflicting selection")
		}
		selection = map[string]any{"seller_ids": []string{future}}
		if decide(sellerOrigin, true).Code != 403 {
			t.Fatal("accepted unauthorized selection")
		}
		selection = map[string]any{"seller_ids": []string{seller, second}}
		if all {
			selection = map[string]any{"all_campaigns": true}
		}
		selection["session_days"] = 8
		if decide(sellerOrigin, true).Code != 400 {
			t.Fatal("accepted unknown consent duration")
		}
		selection["session_days"] = 7
		approved := decide(sellerOrigin, true)
		if approved.Code != 200 || json.Unmarshal(approved.Body.Bytes(), &result) != nil {
			t.Fatalf("account consent %d", approved.Code)
		}
		callback, _ = url.Parse(result.Redirect)
		token := redeem(verifier, mcpResource)
		if token.Code != 200 || json.Unmarshal(token.Body.Bytes(), &access) != nil {
			t.Fatal("redeem account grant")
		}
		grant := uuid.MustParse(result.GrantID)
		if access.Refresh == "" || access.Seconds != 3600 {
			t.Fatal("missing renewable connection")
		}
		original := access
		var deadline time.Time
		if err := db.Pool().QueryRow(t.Context(), `SELECT expires_at FROM seller_mcp_grants WHERE id=$1`, grant).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
		if d := time.Until(deadline); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour {
			t.Fatal("unexpected session deadline")
		}
		for _, args := range []url.Values{{"resource": {"https://other.invalid"}}, {"client_id": {"another-client"}}, {"client_id": {otherClient}}, {"scope": {"analytics:write"}}} {
			if status, _ := refresh(original.Refresh, args); status != 400 {
				t.Fatal("refresh changed grant binding")
			}
		}
		if _, err := db.Pool().Exec(t.Context(), `UPDATE seller_mcp_grants SET access_expires_at=now()-interval '1 second' WHERE id=$1`, grant); err != nil {
			t.Fatal(err)
		}
		if intro("delegate-account", original.Token).Active {
			t.Fatal("expired access token authorized a call")
		}
		status, renewed := refresh(original.Refresh, nil)
		if status != 200 || renewed.Token == original.Token || renewed.Refresh == "" || renewed.Refresh == original.Refresh || renewed.Seconds != 3600 {
			t.Fatal("silent rotation failed")
		}
		access = renewed
		if intro("delegate-account", original.Token).Active {
			t.Fatal("old access token survived rotation")
		}
		stored, err := db.ActiveMCPSelection(t.Context(), testUserID, grant)
		if err != nil || !stored.Allows(second) || stored.Allows(future) != all {
			t.Fatal("wrong stored selection")
		}
		provisional := intro("delegate-account", access.Token)
		if !provisional.Active || intro("consume", provisional.Proof, second).Active {
			t.Fatal("unresolved account delegation authorized report")
		}
		if !intro("consume-discovery", intro("delegate-account", access.Token).Proof).Active {
			t.Fatal("account discovery failed")
		}
		proof := "aurum_dlg_" + randomToken()
		if err = db.IssueMCPReport(t.Context(), testUserID, grant, second, hashValue(proof)); err != nil {
			t.Fatal(err)
		}
		if intro("consume", proof, seller).Active {
			t.Fatal("proof changed cabinet")
		}
		proof = "aurum_dlg_" + randomToken()
		if err = db.IssueMCPReport(t.Context(), testUserID, grant, second, hashValue(proof)); err != nil {
			t.Fatal(err)
		}
		if !intro("consume", proof, second).Active || intro("consume", proof, second).Active {
			t.Fatal("exact one-use report proof")
		}
		if !all {
			if status, _ := refresh(original.Refresh, nil); status != 400 {
				t.Fatal("refresh replay accepted")
			}
			if status, _ := refresh(renewed.Refresh, nil); status != 400 || intro("delegate-account", renewed.Token).Active {
				t.Fatal("replay did not revoke connection")
			}
		} else {
			if _, err := db.Pool().Exec(t.Context(), `UPDATE seller_mcp_grants SET expires_at=now()+interval '40 seconds' WHERE id=$1`, grant); err != nil {
				t.Fatal(err)
			}
			status, last := refresh(renewed.Refresh, nil)
			if status != 200 || last.Seconds <= 0 || last.Seconds > 40 {
				t.Fatal("rotation exceeded fixed deadline")
			}
			if _, err := db.Pool().Exec(t.Context(), `UPDATE seller_mcp_grants SET expires_at=now()-interval '1 second' WHERE id=$1`, grant); err != nil {
				t.Fatal(err)
			}
			if status, _ := refresh(last.Refresh, nil); status != 400 || intro("delegate-account", last.Token).Active {
				t.Fatal("expired connection could still operate")
			}
			if err = db.RevokeMCP(t.Context(), testUserID, grant); err != nil {
				t.Fatal(err)
			}
		}
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

func TestMCPEligibilityPlatformAdmin(t *testing.T) {
	th := newTestHarness(t)
	ca := &x509.Certificate{Raw: []byte("test root")}
	client := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
	o := sellerOAuth{Handler: th.handler, routerCA: ca}
	for _, tc := range []struct {
		name   string
		roles  []string
		err    error
		status int
		admin  bool
	}{
		{"platform administrator", []string{"platform_admin"}, nil, 200, true},
		{"platform manager", []string{"platform_manager"}, nil, 200, false},
		{"tenant member", nil, nil, 200, false},
		{"role lookup fails", nil, errors.New("unavailable"), 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th.mock.listSubjectRolesFn = func(_ context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
				if req.Subject != testUserID.String() || req.ScopeType != "platform" || req.ScopeId != "" {
					t.Fatalf("unexpected role lookup %v", req)
				}
				return &pb.ListSubjectRolesResponse{Roles: tc.roles}, tc.err
			}
			r := httptest.NewRequest(http.MethodPost, "/svc/authn/mcp/eligible", strings.NewReader(`{"subject":"`+testUserID.String()+`"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Gateway-Subject", "svc:aurumskynet-campaigns")
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{client, ca}}}
			w := httptest.NewRecorder()
			o.eligible(w, r)
			var body struct {
				PlatformAdmin bool `json:"platform_admin"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != tc.status || body.PlatformAdmin != tc.admin {
				t.Fatalf("status %d, response %s", w.Code, w.Body)
			}
		})
	}
}
