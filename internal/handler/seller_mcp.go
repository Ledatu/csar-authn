package handler

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/httpx"
	"golang.org/x/oauth2"
)

const mcpResource = "https://mcp.aurum-sky.net"
const mcpIssuer = "https://id.aurum-sky.net"
const sellerOrigin = "https://seller.aurum-sky.net"
const oauthAPI = "https://api.aurum-sky.net/oauth/mcp"
const sellerRouterCN = "aurum-api-router-client"
const consentCookie = "__Host-aurum-mcp-consent"

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

type sellerOAuth struct {
	*Handler
	grants             store.MCPGrantStore
	clientID, redirect string
	routerCA           *x509.Certificate
}

func (h *Handler) RegisterSellerMCP(mux *http.ServeMux, clientID, redirect, routerCAFile string, listener *tls.Config) error {
	if clientID == "" && redirect == "" {
		return nil
	}
	if clientID == "" || len(clientID) > 128 || !validMCPRedirect(redirect) {
		return errors.New("invalid pre-registered seller MCP client or redirect")
	}
	grants, ok := h.store.(store.MCPGrantStore)
	if !ok {
		return errors.New("seller MCP requires a grant store")
	}
	if listener == nil || listener.ClientAuth != tls.RequireAndVerifyClientCert || listener.ClientCAs == nil {
		return errors.New("seller MCP requires a verified client TLS listener")
	}
	data, err := os.ReadFile(routerCAFile)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("seller MCP requires one dedicated router CA certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		return errors.New("invalid seller router CA")
	}
	if _, err := ca.Verify(x509.VerifyOptions{Roots: listener.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		return errors.New("seller router CA must be separate from general service trust")
	}
	listener.ClientCAs.AddCertWithConstraint(ca, func(chain []*x509.Certificate) error {
		if len(chain) == 0 || chain[0].Subject.CommonName != sellerRouterCN {
			return errors.New("unexpected seller router identity")
		}
		return nil
	})
	o := &sellerOAuth{Handler: h, grants: grants, clientID: clientID, redirect: redirect, routerCA: ca}
	mux.HandleFunc("POST /internal/seller-mcp/consume-discovery", o.introspect)
	mux.HandleFunc("POST /svc/authn/mcp/eligible", o.eligible)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", o.metadata)
	mux.HandleFunc("GET /oauth/mcp/authorize", o.authorize)
	mux.HandleFunc("POST /oauth/mcp/token", o.token)
	mux.HandleFunc("POST /oauth/mcp/consent", o.consent)
	mux.HandleFunc("GET /oauth/mcp/connections", o.connections)
	mux.HandleFunc("DELETE /oauth/mcp/connections/{id}", o.revoke)
	mux.HandleFunc("POST /internal/seller-mcp/delegate-account", o.introspect)
	mux.HandleFunc("POST /internal/seller-mcp/delegate", o.introspect)
	mux.HandleFunc("POST /internal/seller-mcp/consume", o.introspect)
	return nil
}

// Both endpoint spellings identify the same HTTPS origin and root path.
func validMCPResource(resource string) bool {
	return resource == mcpResource || resource == mcpResource+"/"
}

func validMCPRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return false
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
	return u.Scheme == "https" || (u.Scheme == "http" && loopback)
}

func (o *sellerOAuth) metadata(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         mcpIssuer,
		"authorization_endpoint":                         oauthAPI + "/authorize",
		"token_endpoint":                                 oauthAPI + "/token",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{store.APIKeyScopeAnalyticsRead},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
	})
}
func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, status, map[string]string{"error": code})
}
func uniqueParams(v url.Values) bool {
	for _, vs := range v {
		if len(vs) != 1 {
			return false
		}
	}
	return true
}

func (o *sellerOAuth) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q, err := url.ParseQuery(r.URL.RawQuery)
	challenge, decodeErr := base64.RawURLEncoding.Strict().DecodeString(q.Get("code_challenge"))
	if err != nil || len(r.URL.RawQuery) > 4096 || !uniqueParams(q) ||
		q.Get("response_type") != "code" || q.Get("client_id") != o.clientID || q.Get("redirect_uri") != o.redirect ||
		q.Get("scope") != store.APIKeyScopeAnalyticsRead || !validMCPResource(q.Get("resource")) ||
		q.Get("code_challenge_method") != "S256" || decodeErr != nil || len(challenge) != 32 || len(q.Get("state")) > 512 {
		oauthError(w, 400, "invalid_request")
		return
	}
	id, browser := randomToken(), randomToken()
	err = o.grants.BeginMCP(r.Context(), store.MCPRequest{ID: id, BrowserHash: hashValue(browser), ClientID: o.clientID, RedirectURI: o.redirect, State: q.Get("state"), Challenge: q.Get("code_challenge")})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: consentCookie, Value: browser, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	// The existing portal accepts this URL during a rolling upgrade. The account UI forwards it to /mcp.
	http.Redirect(w, r, sellerOrigin+"/developer-api?"+url.Values{"mcp_request": {id}, "mcp_client": {o.clientID}}.Encode(), http.StatusSeeOther)
}

func (o *sellerOAuth) consent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Origin") != sellerOrigin {
		oauthError(w, 403, "access_denied")
		return
	}
	user, ok := o.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	cookie, err := r.Cookie(consentCookie)
	var in struct {
		store.MCPSelection
		Request  string `json:"request"`
		Seller   string `json:"seller_id"`
		Decision string `json:"decision"`
		Client   string `json:"client_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if err != nil || len(cookie.Value) != 43 || httpx.ReadJSON(r, &in) != nil || len(in.Request) != 43 ||
		in.Client != o.clientID || (in.Decision != "approve" && in.Decision != "deny") {
		oauthError(w, 400, "invalid_request")
		return
	}
	code, codeHash := "", ""
	if in.Decision == "approve" {
		if in.Seller != "" {
			if in.AllCampaigns || len(in.SellerIDs) > 0 {
				oauthError(w, 400, "invalid_request")
				return
			}
			in.SellerIDs = []string{in.Seller}
		}
		if len(in.SellerIDs) > 256 || in.AllCampaigns != (len(in.SellerIDs) == 0) {
			oauthError(w, 400, "invalid_request")
			return
		}
		slices.Sort(in.SellerIDs)
		for i, seller := range in.SellerIDs {
			if !validWBSellerID(seller) || i > 0 && seller == in.SellerIDs[i-1] {
				oauthError(w, 400, "invalid_request")
				return
			}
			if !o.allowSellerScopes(w, r, user.ID, seller, []string{store.APIKeyScopeAnalyticsRead}) {
				return
			}
		}
		code = "ac_" + randomToken()
		codeHash = hashValue(code)
	}
	binding := store.MCPRequest{ID: in.Request, BrowserHash: hashValue(cookie.Value), ClientID: o.clientID, RedirectURI: o.redirect}
	tx, err := o.grants.DecideMCP(r.Context(), binding, user.ID, in.MCPSelection, codeHash)
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, 400, "invalid_request")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	params := url.Values{"iss": {mcpIssuer}}
	if tx.State != "" {
		params.Set("state", tx.State)
	}
	if code != "" {
		params.Set("code", code)
	} else {
		params.Set("error", "access_denied")
	}
	http.SetCookie(w, &http.Cookie{Name: consentCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	response := map[string]string{"redirect": tx.RedirectURI + "?" + params.Encode()}
	if tx.GrantID != uuid.Nil {
		response["grant_id"] = tx.GrantID.String()
	}
	httpx.WriteJSON(w, 200, response)
}

func (o *sellerOAuth) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.ParseForm() != nil || !uniqueParams(r.PostForm) {
		oauthError(w, 400, "invalid_request")
		return
	}
	q := r.PostForm
	if q.Get("grant_type") != "authorization_code" {
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	if q.Get("client_id") != o.clientID || q.Get("redirect_uri") != o.redirect || !validMCPResource(q.Get("resource")) ||
		!verifierPattern.MatchString(q.Get("code_verifier")) || !strings.HasPrefix(q.Get("code"), "ac_") {
		oauthError(w, 400, "invalid_grant")
		return
	}
	access := "aurum_mcp_" + randomToken()
	err := o.grants.RedeemMCP(r.Context(), hashValue(q.Get("code")), o.clientID, o.redirect, oauth2.S256ChallengeFromVerifier(q.Get("code_verifier")), hashValue(access))
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, 400, "invalid_grant")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"access_token": access, "token_type": "Bearer", "scope": store.APIKeyScopeAnalyticsRead, "expires_in": 3600})
}

// The listener also trusts the general service CA. Delegation requires a chain
// rooted in the dedicated seller router CA, even when another leaf has the same name.
func (o *sellerOAuth) verifiedRouter(state *tls.ConnectionState) bool {
	if state != nil {
		for _, chain := range state.VerifiedChains {
			if len(chain) >= 2 && chain[0].Subject.CommonName == sellerRouterCN && chain[len(chain)-1].Equal(o.routerCA) {
				return true
			}
		}
	}
	return false
}

func (o *sellerOAuth) introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !o.verifiedRouter(r.TLS) {
		oauthError(w, 403, "access_denied")
		return
	}
	var body struct {
		Token  string `json:"token"`
		Seller string `json:"seller_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if httpx.ReadJSON(r, &body) != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	account := r.URL.Path == "/internal/seller-mcp/delegate-account"
	delegate := account || r.URL.Path == "/internal/seller-mcp/delegate"
	prefix := "aurum_dlg_"
	if delegate {
		prefix = "aurum_mcp_"
	}
	if !strings.HasPrefix(body.Token, prefix) || len(body.Token) != len(prefix)+43 {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	var g store.MCPGrant
	var err error
	proof := ""
	if delegate {
		proof = "aurum_dlg_" + randomToken()
		g, err = o.grants.DelegateMCP(r.Context(), hashValue(body.Token), hashValue(proof), account)
	} else {
		g, err = o.grants.ConsumeMCP(r.Context(), hashValue(body.Token))
	}
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	discovery := r.URL.Path == "/internal/seller-mcp/consume-discovery"
	if discovery && !g.DiscoveryOnly || delegate && !account && g.SellerID == "" {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	if !delegate && !discovery {
		requested := body.Seller
		if requested == "" {
			requested = g.SellerID
		} // legacy single-cabinet gateway
		if g.DiscoveryOnly || !validWBSellerID(requested) || !g.Allows(requested) ||
			(g.ReportSeller != "" && requested != g.ReportSeller) || (g.ReportSeller == "" && requested != g.SellerID) {
			httpx.WriteJSON(w, 200, map[string]bool{"active": false})
			return
		}
		g.SellerID = requested
	}
	httpx.WriteJSON(w, 200, map[string]any{"active": true, "account_grant": account || discovery, "discovery": discovery, "subject": g.OwnerID, "credential_id": g.ID, "seller_id": g.SellerID, "scopes": []string{store.APIKeyScopeAnalyticsRead}, "expires_at": g.ExpiresAt, "delegated_token": proof})
}
func (o *sellerOAuth) connections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := o.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	grants, err := o.grants.ListMCP(r.Context(), u.ID)
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"items": grants})
}
func (o *sellerOAuth) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != sellerOrigin {
		oauthError(w, http.StatusForbidden, "access_denied")
		return
	}
	u, ok := o.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	err = o.grants.RevokeMCP(r.Context(), u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, 404, "invalid_grant")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
