package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/lock"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/redis/go-redis/v9"
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
	grants   store.MCPGrantStore
	clients  sellerMCPRegistry
	routerCA *x509.Certificate
	dynamic  *mcpDynamicClients
}

// SellerMCPOAuthOptions makes issuer enablement independent of a vendor list.
// Dynamic onboarding is opt-in and requires a bounded Redis client. The caller
// owns Redis/HTTP shutdown; the production HTTP client must enforce public HTTPS.
type SellerMCPOAuthOptions struct {
	Enabled      bool
	Dynamic      bool
	Clients      []SellerMCPClient
	RouterCAFile string
	Listener     *tls.Config
	Redis        *redis.Client
	HTTPClient   *http.Client
}

func (h *Handler) RegisterSellerMCP(mux *http.ServeMux, clientID, redirect, routerCAFile string, listener *tls.Config, extra ...SellerMCPClient) error {
	clients, err := newSellerMCPRegistry(clientID, redirect, extra)
	if err != nil {
		return err
	}
	return h.registerSellerMCP(mux, clients, SellerMCPOAuthOptions{Enabled: len(clients) > 0, RouterCAFile: routerCAFile, Listener: listener})
}

func (h *Handler) RegisterSellerMCPWithOptions(mux *http.ServeMux, opts SellerMCPOAuthOptions) error {
	clients, err := newSellerMCPRegistry("", "", opts.Clients)
	if err != nil {
		return err
	}
	return h.registerSellerMCP(mux, clients, opts)
}

func (h *Handler) registerSellerMCP(mux *http.ServeMux, clients sellerMCPRegistry, opts SellerMCPOAuthOptions) error {
	if !opts.Enabled {
		if opts.Dynamic {
			return errors.New("dynamic MCP onboarding requires the issuer to be enabled")
		}
		return nil
	}
	grants, ok := h.store.(store.MCPGrantStore)
	if !ok {
		return errors.New("seller MCP requires a grant store")
	}
	ca, err := h.registerRouterCA(opts.RouterCAFile, opts.Listener)
	if err != nil {
		return err
	}
	o := &sellerOAuth{Handler: h, grants: grants, clients: clients, routerCA: ca}
	if opts.Dynamic {
		clientStore, ok := h.store.(store.MCPClientStore)
		if !ok || opts.Redis == nil || opts.HTTPClient == nil {
			return errors.New("dynamic MCP onboarding requires client storage, Redis and public HTTPS transport")
		}
		limiter, err := usagebudget.New(opts.Redis, "authn:mcp:", 200*time.Millisecond)
		if err != nil {
			return err
		}
		o.dynamic = &mcpDynamicClients{store: clientStore, cache: opts.Redis, http: opts.HTTPClient,
			limiter: limiter, locker: lock.NewRedisLocker(opts.Redis), slots: make(chan struct{}, 8)}
		mux.HandleFunc("POST /oauth/mcp/register", o.registerClient)
	}
	mux.HandleFunc("POST /internal/seller-mcp/v1/introspect", o.introspect)
	mux.HandleFunc("POST /internal/seller-mcp/consume-discovery", o.introspect)
	mux.HandleFunc("POST /svc/authn/mcp/eligible", o.eligible)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", o.metadata)
	mux.HandleFunc("GET /oauth/mcp/authorize", o.authorize)
	mux.HandleFunc("POST /oauth/mcp/token", o.token)
	mux.HandleFunc("POST /oauth/mcp/consent", o.consent)
	mux.HandleFunc("GET /oauth/mcp/requests/{id}", o.requestInfo)
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
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(raw, "*#") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || !uniqueParams(query) {
		return false
	}
	for _, reserved := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		if query.Has(reserved) {
			return false
		}
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
	return u.Scheme == "https" || (u.Scheme == "http" && loopback)
}

func (o *sellerOAuth) metadata(w http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"issuer":                                         mcpIssuer,
		"authorization_endpoint":                         oauthAPI + "/authorize",
		"token_endpoint":                                 oauthAPI + "/token",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{store.APIKeyScopeAnalyticsRead},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
	}
	if o.dynamic != nil {
		metadata["client_id_metadata_document_supported"] = true
		metadata["registration_endpoint"] = oauthAPI + "/register"
	}
	httpx.WriteJSON(w, http.StatusOK, metadata)
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
	clientID, redirect := q.Get("client_id"), q.Get("redirect_uri")
	if err != nil || len(r.URL.RawQuery) > 4096 || !uniqueParams(q) ||
		q.Get("response_type") != "code" || !caller.ValidClientID(clientID) || clientID == "" ||
		q.Get("scope") != store.APIKeyScopeAnalyticsRead || !validMCPResource(q.Get("resource")) ||
		q.Get("code_challenge_method") != "S256" || decodeErr != nil || len(challenge) != 32 || len(q.Get("state")) > 512 {
		oauthError(w, 400, "invalid_request")
		return
	}
	name, refreshAllowed := clientID, true
	if o.dynamic != nil {
		if err := o.dynamic.admit(r.Context(), "mcp.authorization", requestPeer(r), 600, time.Minute); err != nil {
			o.clientError(w, err)
			return
		}
	}
	if !o.clients.allows(clientID, redirect) {
		if o.dynamic == nil {
			oauthError(w, 400, "invalid_request")
			return
		}
		client, err := o.dynamic.resolve(r.Context(), clientID)
		if err != nil {
			o.clientError(w, err)
			return
		}
		if !dynamicMCPRedirectAllowed(client, redirect) {
			oauthError(w, 400, "invalid_request")
			return
		}
		name, refreshAllowed = client.ClientName, slices.Contains(client.GrantTypes, "refresh_token")
	}
	id, browser := randomToken(), randomToken()
	err = o.grants.BeginMCP(r.Context(), store.MCPRequest{ID: id, BrowserHash: hashValue(browser), ClientID: clientID, ClientName: name, RefreshAllowed: &refreshAllowed, RedirectURI: redirect, State: q.Get("state"), Challenge: q.Get("code_challenge")})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: consentCookie, Value: browser, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	// The existing portal accepts this URL during a rolling upgrade. The account UI forwards it to /mcp.
	http.Redirect(w, r, sellerOrigin+"/developer-api?"+url.Values{"mcp_request": {id}, "mcp_client": {clientID}}.Encode(), http.StatusSeeOther)
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
		SessionDays int        `json:"session_days"`
		Request     string     `json:"request"`
		Seller      string     `json:"seller_id"`
		Decision    string     `json:"decision"`
		Client      string     `json:"client_id"`
		CallerID    *uuid.UUID `json:"caller_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if err != nil || len(cookie.Value) != 43 || httpx.ReadJSON(r, &in) != nil || len(in.Request) != 43 ||
		(in.SessionDays != 0 && in.SessionDays != store.MCPConnectionDays) || (in.Decision != "approve" && in.Decision != "deny") {
		oauthError(w, 400, "invalid_request")
		return
	}
	if in.Client == "" || !caller.ValidClientID(in.Client) {
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
	binding := store.MCPRequest{CallerID: in.CallerID, SessionDays: in.SessionDays, ID: in.Request, BrowserHash: hashValue(cookie.Value), ClientID: in.Client}
	binding.RedirectURI, err = o.grants.MCPRequestRedirect(r.Context(), binding)
	if errors.Is(err, store.ErrNotFound) || err == nil && (!validMCPRedirect(binding.RedirectURI) || o.dynamic == nil && !o.clients.allows(in.Client, binding.RedirectURI)) {
		oauthError(w, 400, "invalid_request")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
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
	callback, err := url.Parse(tx.RedirectURI)
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if callback.RawQuery != "" {
		callback.RawQuery += "&"
	}
	callback.RawQuery += params.Encode()
	callback.ForceQuery = false
	response := map[string]string{"redirect": callback.String()}
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
	access := "aurum_mcp_" + randomToken()
	refresh := "aurum_refresh_" + randomToken()
	var lifetime store.MCPTokenLifetime
	var err error
	clientID := q.Get("client_id")
	if clientID == "" || !caller.ValidClientID(clientID) || r.Header.Get("Authorization") != "" || q.Has("client_secret") || q.Has("client_assertion") || q.Has("client_assertion_type") {
		oauthError(w, 400, "invalid_client")
		return
	}
	switch q.Get("grant_type") {
	case "authorization_code":
		// The one-use stored code, not a mutable registry/cache, binds this exact
		// client and callback. Refresh similarly binds the persisted client/grant.
		if !validMCPRedirect(q.Get("redirect_uri")) || !validMCPResource(q.Get("resource")) ||
			!verifierPattern.MatchString(q.Get("code_verifier")) || !strings.HasPrefix(q.Get("code"), "ac_") {
			oauthError(w, 400, "invalid_grant")
			return
		}
		lifetime, err = o.grants.RedeemMCP(r.Context(), hashValue(q.Get("code")), clientID, q.Get("redirect_uri"), oauth2.S256ChallengeFromVerifier(q.Get("code_verifier")), hashValue(access), hashValue(refresh))
	case "refresh_token":
		// Omitted scope/resource retain the original single-audience grant.
		if (q.Has("resource") && !validMCPResource(q.Get("resource"))) || (q.Has("scope") && q.Get("scope") != store.APIKeyScopeAnalyticsRead) ||
			!strings.HasPrefix(q.Get("refresh_token"), "aurum_refresh_") || len(q.Get("refresh_token")) != len("aurum_refresh_")+43 {
			oauthError(w, 400, "invalid_grant")
			return
		}
		lifetime, err = o.grants.RefreshMCP(r.Context(), clientID, hashValue(q.Get("refresh_token")), hashValue(access), hashValue(refresh))
	default:
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, 400, "invalid_grant")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	response := map[string]any{"access_token": access, "token_type": "Bearer", "scope": store.APIKeyScopeAnalyticsRead, "expires_in": lifetime.Seconds}
	if lifetime.Renewable {
		response["refresh_token"] = refresh
	}
	httpx.WriteJSON(w, 200, response)
}

// The listener also trusts the general service CA. Delegation requires a chain
// rooted in the dedicated seller router CA, even when another leaf has the same name.
func (o *sellerOAuth) verifiedRouter(state *tls.ConnectionState) bool {
	return verifiedRouterCA(state, o.routerCA)
}

func (o *sellerOAuth) introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !o.verifiedRouter(r.TLS) {
		oauthError(w, 403, "access_denied")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var request authntokens.DelegationRequest
	portable := r.URL.Path == "/internal/seller-mcp/v1/introspect"
	singleExchange := r.URL.Path == "/internal/seller-mcp/delegate"
	if portable {
		if httpx.ReadJSON(r, &request) != nil {
			oauthError(w, 400, "invalid_request")
			return
		}
		if request.Audience != mcpResource || request.Scope != store.APIKeyScopeAnalyticsRead ||
			!authntokens.IsDelegation(request.Purpose) || (request.Purpose == authntokens.GrantResource) != (request.ResourceID != "") {
			httpx.WriteJSON(w, 200, authntokens.DelegationResult{})
			return
		}
	} else {
		var body struct {
			Token  string `json:"token"`
			Seller string `json:"seller_id"`
		}
		if httpx.ReadJSON(r, &body) != nil {
			oauthError(w, 400, "invalid_request")
			return
		}
		request.Token, request.ResourceID = body.Token, body.Seller
		switch r.URL.Path {
		case "/internal/seller-mcp/delegate-account", "/internal/seller-mcp/delegate":
			request.Purpose = authntokens.GrantExchange
		case "/internal/seller-mcp/consume-discovery":
			request.Purpose = authntokens.GrantDiscovery
		case "/internal/seller-mcp/consume":
			request.Purpose = authntokens.GrantResource
		}
	}
	delegate := request.Purpose == authntokens.GrantExchange
	account := delegate && !singleExchange
	discovery := request.Purpose == authntokens.GrantDiscovery
	prefix := "aurum_dlg_"
	if delegate {
		prefix = "aurum_mcp_"
	}
	if !strings.HasPrefix(request.Token, prefix) || len(request.Token) != len(prefix)+43 {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	var g store.MCPGrant
	var err error
	proof := ""
	if delegate {
		proof = "aurum_dlg_" + randomToken()
		g, err = o.grants.DelegateMCP(r.Context(), hashValue(request.Token), hashValue(proof), account)
	} else {
		g, err = o.grants.ConsumeMCP(r.Context(), hashValue(request.Token))
	}
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if discovery && !g.DiscoveryOnly || delegate && !account && g.SellerID == "" {
		httpx.WriteJSON(w, 200, map[string]bool{"active": false})
		return
	}
	if !delegate && !discovery {
		requested := request.ResourceID
		if !portable && requested == "" {
			requested = g.SellerID
		} // legacy single-cabinet gateway
		if g.DiscoveryOnly || !validWBSellerID(requested) || !g.Allows(requested) ||
			(g.ReportSeller != "" && requested != g.ReportSeller) || (g.ReportSeller == "" && requested != g.SellerID) {
			httpx.WriteJSON(w, 200, map[string]bool{"active": false})
			return
		}
		g.SellerID = requested
	}
	identity, err := o.credentialIdentity(r.Context(), g.OwnerID, caller.OAuthAccess, g.ID.String())
	if errors.Is(err, errCallerRevoked) {
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	identity.ClientID, identity.ConnectionID = g.ClientID, g.ID.String()
	if !delegate {
		identity.CredentialKind = caller.DelegationProof
	}
	if err := identity.Validate(); err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if portable {
		result := authntokens.DelegationResult{Identity: identity, Active: true, Purpose: request.Purpose, Audience: mcpResource, Scope: store.APIKeyScopeAnalyticsRead, Subject: g.OwnerID.String(), CredentialID: g.ID.String(), ExpiresAt: g.ExpiresAt, DelegatedToken: proof, ResourceID: request.ResourceID}
		if !discovery && g.SellerID != "" {
			result.Tenant = "wildberries:" + g.SellerID
		}
		httpx.WriteJSON(w, http.StatusOK, result)
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"identity": identity, "active": true, "account_grant": account || discovery, "discovery": discovery, "subject": g.OwnerID, "credential_id": g.ID, "seller_id": g.SellerID, "scopes": []string{store.APIKeyScopeAnalyticsRead}, "expires_at": g.ExpiresAt, "delegated_token": proof})
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
