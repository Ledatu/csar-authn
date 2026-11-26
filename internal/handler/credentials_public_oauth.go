package handler

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/lock"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/redis/go-redis/v9"
)

// PublicOAuthDependencies are startup-owned existing clients, never request policy.
type PublicOAuthDependencies struct {
	Redis      *redis.Client
	HTTPClient *http.Client
}

func (h *Handler) sharedPublicClients(cache *redis.Client, client *http.Client) (*publicOAuthClients, error) {
	if cache == nil || client == nil {
		return nil, errors.New("public client admission dependencies unavailable")
	}
	if h.publicClients != nil {
		return h.publicClients, nil
	}
	st, ok := h.store.(store.OAuthClientStore)
	if !ok {
		return nil, errors.New("public client registry unavailable")
	}
	// Protected identities intentionally preserve all existing admission/cache state.
	limiter, err := usagebudget.New(cache, "authn:mcp:", 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	h.publicClients = &publicOAuthClients{store: st, cache: cache, http: client, limiter: limiter, locker: lock.NewRedisLocker(cache), slots: make(chan struct{}, 8)}
	return h.publicClients, nil
}
func (u *credentialIssuer) publicEnabled() bool {
	return u.cfg.PublicOAuth != nil && u.cfg.PublicOAuth.Enabled
}
func (u *credentialIssuer) publicProfile(id string) *authnconfig.CredentialProfile {
	if !u.publicEnabled() {
		return nil
	}
	for _, binding := range u.cfg.PublicOAuth.Profiles {
		if binding.ProfileID == id {
			return u.profile(id)
		}
	}
	return nil
}
func (u *credentialIssuer) publicResource(resource string) *authnconfig.CredentialProfile {
	if !u.publicEnabled() {
		return nil
	}
	for _, binding := range u.cfg.PublicOAuth.Profiles {
		p := u.profile(binding.ProfileID)
		if p != nil && (resource == p.Audience || slices.Contains(binding.ResourceAliases, resource)) {
			return p
		}
	}
	return nil
}
func (u *credentialIssuer) registerPublicOAuth(mux *http.ServeMux, options []PublicOAuthDependencies) error {
	if !u.publicEnabled() {
		return nil
	}
	if len(options) > 1 {
		return errors.New("ambiguous public OAuth dependencies")
	}
	if u.cfg.PublicOAuth.DynamicClients {
		if len(options) != 1 {
			return errors.New("public OAuth admission dependencies unavailable")
		}
		var err error
		u.clients, err = u.h.sharedPublicClients(options[0].Redis, options[0].HTTPClient)
		if err != nil {
			return err
		}
		mux.HandleFunc("POST /oauth/credentials/register", u.bound(u.publicIngress(u.clients.registerClient)))
	}
	mux.HandleFunc("GET /oauth/credentials/metadata", u.bound(u.publicIngress(u.publicMetadata)))
	mux.HandleFunc("GET /oauth/credentials/authorize", u.bound(u.publicAuthorize))
	mux.HandleFunc("POST /oauth/credentials/deny", u.bound(u.denyAuthorization))
	return nil
}
func (u *credentialIssuer) publicIngress(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, binding := range u.cfg.PublicOAuth.Profiles {
			if p := u.profile(binding.ProfileID); p != nil && u.trusted(r, p.TrustPolicy) {
				next(w, r)
				return
			}
		}
		credentialError(w, http.StatusForbidden)
	}
}
func (u *credentialIssuer) publicMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	scopes := []string{}
	for _, binding := range u.cfg.PublicOAuth.Profiles {
		for _, s := range u.profile(binding.ProfileID).Scopes {
			if !slices.Contains(scopes, s.Scope) {
				scopes = append(scopes, s.Scope)
			}
		}
	}
	out := map[string]any{"issuer": u.cfg.IssuerURL, "authorization_endpoint": u.cfg.PublicOAuth.AuthorizationEndpoint, "token_endpoint": u.cfg.PublicOAuth.TokenEndpoint, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": scopes, "token_endpoint_auth_methods_supported": []string{"none"}, "authorization_response_iss_parameter_supported": true}
	if u.cfg.PublicOAuth.DynamicClients {
		out["client_id_metadata_document_supported"] = true
		out["registration_endpoint"] = u.cfg.PublicOAuth.RegistrationEndpoint
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
func (u *credentialIssuer) publicAuthorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 4096 || !uniqueParams(q) || q.Get("response_type") != "code" || len(q.Get("state")) > 512 {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for k := range q {
		if !slices.Contains([]string{"response_type", "client_id", "redirect_uri", "scope", "resource", "code_challenge", "code_challenge_method", "state"}, k) {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	p := u.publicResource(q.Get("resource"))
	if p == nil || !u.trusted(r, p.TrustPolicy) {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	in := credentialAuthorizationInput{credentialConsentInput: credentialConsentInput{ProfileID: p.ID, Scopes: strings.Split(q.Get("scope"), " "), Namespaces: slices.Clone(p.Namespaces)}, ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), Challenge: q.Get("code_challenge"), ChallengeMethod: q.Get("code_challenge_method"), State: q.Get("state"), resource: q.Get("resource")}
	u.startAuthorization(w, r, &in, true)
}
func (u *credentialIssuer) resolvePublicClient(r *http.Request, id string) (store.OAuthClient, error) {
	if u.clients != nil {
		return u.clients.resolve(r.Context(), id)
	}
	st, ok := u.h.store.(store.OAuthClientStore)
	if !ok {
		return store.OAuthClient{}, errOAuthClientUnavailable
	}
	return st.OAuthClient(r.Context(), id)
}

func (u *credentialIssuer) denyAuthorization(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, true)
	if !ok {
		return
	}
	browser, ok := u.browser(r)
	if !ok {
		credentialError(w, http.StatusForbidden)
		return
	}
	var in struct {
		RequestID string `json:"request_id"`
	}
	if !credentialJSON(w, r, &in) {
		return
	}
	request, err := u.store.DenyCredentialAuthorization(r.Context(), in.RequestID, browser, owner.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrCredentialInvalid) {
			credentialError(w, http.StatusBadRequest)
		} else {
			credentialError(w, http.StatusServiceUnavailable)
		}
		return
	}
	callback, err := url.Parse(request.ClientBinding.RedirectURI)
	if err != nil {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	q := callback.Query()
	q.Set("error", "access_denied")
	q.Set("state", request.State)
	q.Set("iss", u.cfg.IssuerURL)
	callback.RawQuery = q.Encode()
	http.SetCookie(w, &http.Cookie{Name: u.cfg.ConsentCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.Header().Set("Referrer-Policy", "no-referrer")
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"redirect": callback.String()})
}
