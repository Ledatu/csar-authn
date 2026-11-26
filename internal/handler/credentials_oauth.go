package handler

import (
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
	"golang.org/x/oauth2"
)

func (u *credentialIssuer) browser(r *http.Request) (string, bool) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == u.cfg.ConsentCookieName {
			value = c.Value
			count++
		}
	}
	if count != 1 || !validGenericEntropy(value) {
		return "", false
	}
	return hashValue(value), true
}

type credentialAuthorizationInput struct {
	credentialConsentInput
	ClientID        string `json:"client_id"`
	RedirectURI     string `json:"redirect_uri"`
	Challenge       string `json:"code_challenge"`
	ChallengeMethod string `json:"code_challenge_method"`
	State           string `json:"state"`
	resource        string
}

func (u *credentialIssuer) beginAuthorization(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Origin")) != 1 || !slices.Contains(u.cfg.MutationOrigins, r.Header.Get("Origin")) {
		credentialError(w, 403)
		return
	}
	var in credentialAuthorizationInput
	if !credentialJSON(w, r, &in) {
		return
	}
	u.startAuthorization(w, r, &in, false)
}
func (u *credentialIssuer) startAuthorization(w http.ResponseWriter, r *http.Request, in *credentialAuthorizationInput, redirect bool) {
	p := u.profile(in.ProfileID)
	// At authorization start no selector has been consented yet; only requested
	// scopes/namespaces are captured. The owner chooses the actual selector later.
	if p == nil || !caller.ValidClientID(in.ClientID) || in.ClientID == "" || in.ChallengeMethod != "S256" || !authntokens.ValidScopes(in.Scopes) || !authntokens.ValidNamespaces(in.Namespaces) {
		credentialError(w, 400)
		return
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(in.Challenge)
	if err != nil || len(challenge) != 32 {
		credentialError(w, 400)
		return
	}
	if u.publicEnabled() {
		if u.publicProfile(in.ProfileID) == nil || !u.trusted(r, p.TrustPolicy) {
			credentialError(w, 403)
			return
		}
		if u.clients != nil {
			if err := u.clients.admit(r.Context(), "mcp.authorization", requestPeer(r), 600, time.Minute); err != nil {
				publicClientError(w, err)
				return
			}
		}
	}
	client, err := u.resolvePublicClient(r, in.ClientID, in.RedirectURI)
	if err != nil {
		publicClientError(w, err)
		return
	}
	if client.ClientID != in.ClientID || client.AuthMethod != "none" || !slices.Contains(client.GrantTypes, "authorization_code") || !slices.Contains(client.ResponseTypes, "code") || !publicOAuthRedirectAllowed(client, in.RedirectURI) {
		credentialError(w, 400)
		return
	}
	now := time.Now().UTC()
	request := store.CredentialAuthorizationRequest{ID: "req_" + randomToken(), SchemaVersion: 1, BrowserHash: hashValue(randomToken()), ClientBinding: store.CredentialClientBinding{Version: 1, ClientID: client.ClientID, RedirectURI: in.RedirectURI, RefreshAllowed: slices.Contains(client.GrantTypes, "refresh_token"), PKCEChallenge: in.Challenge}, ProfileID: p.ID, ProfileRevision: p.Revision, Audience: p.Audience, Scopes: in.Scopes, Namespaces: in.Namespaces, State: in.State, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if u.publicEnabled() {
		request.ClientBinding.Version = 2
		request.ClientBinding.ClientName = client.ClientName
		request.ClientBinding.Resource = in.resource
		if request.ClientBinding.Resource == "" {
			request.ClientBinding.Resource = p.Audience
		}
	}
	if request.Validate() != nil {
		credentialError(w, 400)
		return
	}
	for _, scope := range request.Scopes {
		if !slices.ContainsFunc(p.Scopes, func(s authnconfig.CredentialScope) bool { return s.Scope == scope }) {
			credentialError(w, 400)
			return
		}
	}
	for _, ns := range request.Namespaces {
		if !slices.Contains(p.Namespaces, ns) {
			credentialError(w, 400)
			return
		}
	}
	browser := randomToken()
	request.BrowserHash = hashValue(browser)
	if err := u.store.BeginCredentialAuthorization(r.Context(), request); err != nil {
		if errors.Is(err, store.ErrCredentialRequestLimit) {
			w.Header().Set("Retry-After", "1")
			credentialError(w, 429)
			return
		}
		credentialError(w, 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: u.cfg.ConsentCookieName, Value: browser, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	consent, _ := url.Parse(u.cfg.ConsentURL)
	q := consent.Query()
	q.Set("credential_request", request.ID)
	consent.RawQuery = q.Encode()
	if redirect {
		http.Redirect(w, r, consent.String(), http.StatusSeeOther)
		return
	}
	httpx.WriteJSON(w, 201, map[string]any{"request_id": request.ID, "consent_url": consent.String(), "expires_at": request.ExpiresAt})
}
func (u *credentialIssuer) authorizationInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	browser, ok := u.browser(r)
	if !ok {
		credentialError(w, 404)
		return
	}
	request, err := u.store.CredentialAuthorization(r.Context(), r.PathValue("request_id"), browser)
	if err != nil {
		credentialError(w, 404)
		return
	}
	p := u.profile(request.ProfileID)
	if p == nil || p.Revision != request.ProfileRevision || p.Audience != request.Audience || request.ClientBinding.Version == 2 && u.publicProfile(p.ID) == nil {
		credentialError(w, 400)
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"request_id": request.ID, "profile_id": request.ProfileID, "audience": request.Audience, "scopes": request.Scopes, "namespaces": request.Namespaces, "client_id": request.ClientBinding.ClientID, "redirect_uri": request.ClientBinding.RedirectURI, "refresh_allowed": request.ClientBinding.RefreshAllowed, "expires_at": request.ExpiresAt, "client_name": request.ClientBinding.ClientName, "grant_ttl_seconds": int64(p.GrantTTL.Duration / time.Second), "access_ttl_seconds": int64(p.AccessTTL.Duration / time.Second)})
}
func (u *credentialIssuer) approveAuthorization(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, true)
	if !ok {
		return
	}
	browser, ok := u.browser(r)
	if !ok {
		credentialError(w, 403)
		return
	}
	var in struct {
		credentialConsentInput
		credentialCallerInput
		RequestID  string `json:"request_id"`
		TTLSeconds *int64 `json:"ttl_seconds,omitempty"`
		Label      string `json:"label"`
	}
	if !credentialJSONLimit(w, r, &in, authntokens.MaxConsentResponseBytes) {
		return
	}
	request, err := u.store.CredentialAuthorization(r.Context(), in.RequestID, browser)
	if err != nil {
		credentialError(w, 400)
		return
	}
	p := u.profile(in.ProfileID)
	if p == nil || p.ID != request.ProfileID || p.Audience != request.Audience || p.Revision != request.ProfileRevision || request.ClientBinding.Version == 2 && u.publicProfile(p.ID) == nil {
		credentialError(w, 400)
		return
	}
	constraints, err := in.constraints(p)
	if err != nil {
		credentialError(w, 400)
		return
	}
	for _, scope := range constraints.Scopes {
		if !slices.Contains(request.Scopes, scope) {
			credentialError(w, 400)
			return
		}
	}
	for _, namespace := range constraints.Namespaces {
		if !slices.Contains(request.Namespaces, namespace) {
			credentialError(w, 400)
			return
		}
	}
	if err := u.checkSelection(r, p, owner.ID.String(), &constraints); err != nil {
		if errors.Is(err, store.ErrCredentialInvalid) {
			credentialError(w, 403)
		} else {
			credentialError(w, 503)
		}
		return
	}
	fresh, err := in.newCaller(owner.ID, in.Label)
	if err != nil {
		credentialError(w, 400)
		return
	}
	cid := uuid.Nil
	if fresh != nil {
		cid = fresh.ID
	} else if in.CallerID != nil {
		cid = *in.CallerID
	}
	ttl := p.GrantTTL.Duration
	if in.TTLSeconds != nil {
		if *in.TTLSeconds < 1 || *in.TTLSeconds > int64(ttl/time.Second) {
			credentialError(w, 400)
			return
		}
		ttl = time.Duration(*in.TTLSeconds) * time.Second
	}
	g := store.CredentialGrant{ID: uuid.New(), SchemaVersion: 1, OwnerID: owner.ID, CallerID: cid, Kind: caller.OAuthAccess, Label: in.Label, Constraints: constraints, ClientBinding: &request.ClientBinding, ExpiresAt: time.Now().Add(ttl)}
	raw, code := genericToken(store.SecretCode)
	code.ID = uuid.New()
	code.GrantID = g.ID
	code.ExpiresAt = minTime(g.ExpiresAt, minTime(request.ExpiresAt, time.Now().Add(5*time.Minute)))
	if err := u.store.ApproveCredentialAuthorization(r.Context(), request.ID, browser, &g, code, fresh); err != nil {
		credentialError(w, 409)
		return
	}
	callback, _ := url.Parse(request.ClientBinding.RedirectURI)
	q := callback.Query()
	q.Set("code", raw)
	q.Set("state", request.State)
	q.Set("iss", u.cfg.IssuerURL)
	callback.RawQuery = q.Encode()
	http.SetCookie(w, &http.Cookie{Name: u.cfg.ConsentCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.Header().Set("Referrer-Policy", "no-referrer")
	httpx.WriteJSON(w, 200, map[string]any{"redirect": callback.String(), "grant_id": g.ID})
}
func (u *credentialIssuer) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Csar-Authorization") != "" || r.ParseForm() != nil || !uniqueParams(r.PostForm) {
		oauthError(w, 400, "invalid_request")
		return
	}
	q := r.PostForm
	for k := range q {
		if !slices.Contains([]string{"grant_type", "client_id", "code", "code_verifier", "redirect_uri", "refresh_token", "resource", "scope"}, k) {
			oauthError(w, 400, "invalid_request")
			return
		}
	}
	raw := q.Get("code")
	purpose := store.SecretCode
	if q.Get("grant_type") == "refresh_token" {
		purpose = store.SecretRefresh
		raw = q.Get("refresh_token")
	} else if q.Get("grant_type") != "authorization_code" {
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	state, p, effective, err := u.state(r.Context(), raw, purpose)
	// A spent refresh is compromise evidence even while its profile is removed
	// or incompatible. Authenticate its original client and commit only authority
	// reduction before evaluating current issuance policy; restoration cannot revive it.
	if purpose == store.SecretRefresh && state.Secret.SpentAt != nil && state.Grant.ClientBinding != nil && q.Get("client_id") == state.Grant.ClientBinding.ClientID {
		use := useCredential(&state)
		use.ClientID = state.Grant.ClientBinding.ClientID
		setAuthenticatedContext(r, &store.User{ID: state.Grant.OwnerID}, credentialIdentity(&state))
		_, replayErr := u.store.ExchangeCredentialSecret(r.Context(), use, nil)
		if errors.Is(replayErr, store.ErrCredentialReplay) || errors.Is(replayErr, store.ErrNotFound) {
			oauthError(w, 400, "invalid_grant")
		} else {
			oauthError(w, 503, "temporarily_unavailable")
		}
		return
	}
	if err != nil || state.Grant.ClientBinding == nil {
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCredentialInvalid) {
			oauthError(w, 503, "temporarily_unavailable")
		} else {
			oauthError(w, 400, "invalid_grant")
		}
		return
	}
	binding := state.Grant.ClientBinding
	if binding.Version == 2 && (u.publicProfile(p.ID) == nil || u.publicResource(binding.Resource) == nil || u.publicResource(binding.Resource).ID != p.ID) {
		oauthError(w, 400, "invalid_grant")
		return
	}
	if q.Get("client_id") != binding.ClientID || q.Has("resource") && q.Get("resource") != p.Audience && (binding.Version != 2 || q.Get("resource") != binding.Resource) || q.Has("scope") && !sameCredentialScopes(q.Get("scope"), effective.Scopes) {
		oauthError(w, 400, "invalid_grant")
		return
	}
	use := useCredential(&state)
	use.ClientID = binding.ClientID
	if purpose == store.SecretCode {
		if !verifierPattern.MatchString(q.Get("code_verifier")) || q.Get("redirect_uri") != binding.RedirectURI {
			oauthError(w, 400, "invalid_grant")
			return
		}
		use.RedirectURI = q.Get("redirect_uri")
		use.PKCEChallenge = oauth2.S256ChallengeFromVerifier(q.Get("code_verifier"))
		if use.PKCEChallenge != binding.PKCEChallenge {
			oauthError(w, 400, "invalid_grant")
			return
		}
	}
	if err := u.checkSelection(r, p, state.Grant.OwnerID.String(), effective); err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	access, a := genericToken(store.SecretAccess)
	a.ID = uuid.New()
	a.GrantID = state.Grant.ID
	a.ExpiresAt = minTime(state.Grant.ExpiresAt, time.Now().Add(p.AccessTTL.Duration))
	next := []store.CredentialSecret{a}
	var refresh string
	if binding.RefreshAllowed {
		var token store.CredentialSecret
		refresh, token = genericToken(store.SecretRefresh)
		token.ID = uuid.New()
		token.GrantID = state.Grant.ID
		token.ExpiresAt = state.Grant.ExpiresAt
		next = append(next, token)
	}
	setAuthenticatedContext(r, &store.User{ID: state.Grant.OwnerID}, credentialIdentity(&state))
	if _, err := u.store.ExchangeCredentialSecret(r.Context(), use, next); err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrCredentialInvalid) || errors.Is(err, store.ErrCredentialReplay) {
			oauthError(w, 400, "invalid_grant")
		} else {
			oauthError(w, 503, "temporarily_unavailable")
		}
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"token_type": "Bearer", "access_token": access, "refresh_token": refresh, "expires_in": max(0, int(time.Until(a.ExpiresAt).Seconds())), "scope": strings.Join(effective.Scopes, " "), "resource": p.Audience})
}

func sameCredentialScopes(raw string, expected []string) bool {
	scopes := strings.Split(raw, " ")
	if !authntokens.ValidScopes(scopes) || len(scopes) != len(expected) {
		return false
	}
	for _, scope := range scopes {
		if !slices.Contains(expected, scope) {
			return false
		}
	}
	return true
}
