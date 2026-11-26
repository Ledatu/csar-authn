package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/stsclient"
)

type credentialTrust struct {
	ca   *x509.Certificate
	peer string
}
type credentialIssuer struct {
	h         *Handler
	cfg       authnconfig.CredentialConfig
	store     store.GenericCredentialStore
	decisions *stsclient.RouterClient
	trust     map[string]credentialTrust
	clients   *publicOAuthClients
}

// RegisterCredentials is startup-only. No endpoint is registered before all
// receiver dependencies and exact feature trust policies have been established.
func (h *Handler) RegisterCredentials(mux *http.ServeMux, listener *tls.Config, decisions *stsclient.RouterClient, options ...PublicOAuthDependencies) error {
	cfg := h.Config()
	if cfg.Credentials == nil || !cfg.Credentials.Enabled {
		return nil
	}
	st, ok := h.store.(store.GenericCredentialStore)
	_, clientsReady := h.store.(store.OAuthClientStore)
	if !ok || !clientsReady || !st.GenericCredentialsReady() || !cfg.Cookie.Secure || !cfg.AuditOutboxEnabled || h.sessMgr == nil || decisions == nil || decisions.Client == nil || !authntokens.ValidAudience(decisions.BaseURL) {
		return errors.New("generic credential dependencies unavailable")
	}
	// Own every startup slice without retaining mutable caller configuration.
	raw, err := json.Marshal(cfg.Credentials)
	if err != nil {
		return err
	}
	var owned authnconfig.CredentialConfig
	if err := json.Unmarshal(raw, &owned); err != nil {
		return err
	}
	u := &credentialIssuer{h: h, cfg: owned, store: st, decisions: decisions, trust: make(map[string]credentialTrust)}
	for _, policy := range owned.TrustPolicies {
		ca, err := h.registerRouterTrust(policy.CAFile, policy.PeerCN, listener)
		if err != nil {
			return err
		}
		u.trust[policy.ID] = credentialTrust{ca: ca, peer: policy.PeerCN}
	}
	if err := u.registerPublicOAuth(mux, options); err != nil {
		return err
	}
	mux.HandleFunc("GET /auth/me/credentials", u.bound(u.list))
	mux.HandleFunc("POST /auth/me/credentials", u.bound(u.create))
	mux.HandleFunc("GET /auth/me/credentials/{grant_id}", u.bound(u.detail))
	mux.HandleFunc("DELETE /auth/me/credentials/{grant_id}", u.bound(u.revoke))
	mux.HandleFunc("POST /internal/credentials/v2/introspect", u.bound(u.introspect))
	mux.HandleFunc("POST /svc/credentials/inspect", u.bound(u.inspect))
	mux.HandleFunc("POST /svc/credentials/evaluate", u.bound(u.evaluate))
	mux.HandleFunc("POST /oauth/credentials/authorize", u.bound(u.beginAuthorization))
	mux.HandleFunc("GET /oauth/credentials/requests/{request_id}", u.bound(u.authorizationInfo))
	mux.HandleFunc("POST /oauth/credentials/approve", u.bound(u.approveAuthorization))
	mux.HandleFunc("POST /oauth/credentials/token", u.bound(u.token))
	return nil
}
func (u *credentialIssuer) profile(id string) *authnconfig.CredentialProfile {
	for i := range u.cfg.Profiles {
		if u.cfg.Profiles[i].ID == id {
			return &u.cfg.Profiles[i]
		}
	}
	return nil
}
func (u *credentialIssuer) trusted(r *http.Request, policy string) bool {
	t, ok := u.trust[policy]
	return ok && verifiedRouterTrust(r.TLS, t.ca, t.peer)
}
func credentialError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
func credentialJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	return credentialJSONLimit(w, r, out, authntokens.MaxCandidateRequestBytes)
}
func credentialJSONLimit(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if httpx.ReadStrictJSON(r, out) != nil {
		credentialError(w, 400)
		return false
	}
	return true
}

func (u *credentialIssuer) owner(w http.ResponseWriter, r *http.Request, mutation bool) (*store.User, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get(gatewayctx.HeaderCsarAuthorization) != "" || r.Header.Get("Authorization") != "" {
		credentialError(w, 401)
		return nil, false
	}
	if mutation && (len(r.Header.Values("Origin")) != 1 || !slices.Contains(u.cfg.MutationOrigins, r.Header.Get("Origin"))) {
		credentialError(w, 403)
		return nil, false
	}
	return u.h.directCredentialOwner(w, r)
}
func genericToken(p store.SecretPurpose) (string, store.CredentialSecret) {
	raw := "csar_v1_" + string(p) + "_" + randomToken()
	return raw, store.CredentialSecret{Purpose: p, FormatVersion: store.CredentialFormatVersion, TokenHash: hashValue(raw)}
}
func genericPurpose(raw string) (store.SecretPurpose, bool) {
	for _, p := range []store.SecretPurpose{store.SecretAccess, store.SecretCode, store.SecretRefresh} {
		prefix := "csar_v1_" + string(p) + "_"
		if strings.HasPrefix(raw, prefix) && validGenericEntropy(strings.TrimPrefix(raw, prefix)) {
			return p, true
		}
	}
	for _, p := range []store.SecretPurpose{store.SecretExchange, store.SecretDiscovery, store.SecretResource} {
		if strings.HasPrefix(raw, "csar_v1_"+string(p)+".") {
			_, ok := proofBinding(raw)
			return p, ok
		}
	}
	return "", false
}

func (u *credentialIssuer) state(ctx context.Context, raw string, purpose store.SecretPurpose) (store.CredentialState, *authnconfig.CredentialProfile, *authntokens.GrantConstraints, error) {
	p, ok := genericPurpose(raw)
	if !ok || p != purpose {
		return store.CredentialState{}, nil, nil, store.ErrNotFound
	}
	var s store.CredentialState
	var err error
	if purpose == store.SecretRefresh {
		s, err = u.store.FindCredentialRefresh(ctx, hashValue(raw))
	} else {
		s, err = u.store.FindCredentialSecret(ctx, hashValue(raw), purpose, 1)
	}
	if err != nil {
		return s, nil, nil, err
	}
	profile := u.profile(s.Grant.Constraints.ProfileID)
	effective, err := profile.Narrow(&s.Grant.Constraints)
	if err != nil {
		return s, profile, nil, store.ErrCredentialInvalid
	}
	return s, profile, effective, nil
}

// Providing-service wire models stay here; the reusable authenticated transport
// comes from Core. Background decision capability must be explicitly configured
// for this issuer service; raw HTTP requests never choose a subject/permission.
type credentialDecision struct {
	Resource authntokens.ResourceRef `json:"resource"`
	Allowed  bool                    `json:"allowed"`
	Scope    *authntokens.ScopeRef   `json:"scope,omitempty"`
}

func (u *credentialIssuer) decide(ctx context.Context, profile *authnconfig.CredentialProfile, subject, scope string, refs []authntokens.ResourceRef) ([]credentialDecision, error) {
	if authntokens.ValidateResources(refs, authntokens.MaxDecisionResources) != nil {
		return nil, store.ErrCredentialInvalid
	}
	var decisionProfile string
	for _, s := range profile.Scopes {
		if s.Scope == scope {
			decisionProfile = s.DecisionProfile
		}
	}
	if decisionProfile == "" {
		return nil, store.ErrCredentialInvalid
	}
	body, _ := json.Marshal(struct {
		Version   int                       `json:"version"`
		Profile   string                    `json:"profile"`
		Audience  string                    `json:"audience"`
		Subject   string                    `json:"subject"`
		Mode      string                    `json:"subject_mode"`
		Resources []authntokens.ResourceRef `json:"resources"`
	}{1, decisionProfile, profile.Audience, subject, "background", refs})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(u.decisions.BaseURL, "/")+"/svc/decisions/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.decisions.Client.Do(req)
	if err != nil {
		return nil, errors.New("authorization unavailable")
	}
	defer resp.Body.Close() //nolint:errcheck // response body close cannot change authorization
	var out struct {
		Version  int                  `json:"version"`
		Profile  string               `json:"profile"`
		Audience string               `json:"audience"`
		Subject  string               `json:"subject"`
		Results  []credentialDecision `json:"results"`
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("authorization unavailable")
	}
	responseRequest := &http.Request{Body: http.MaxBytesReader(nil, resp.Body, authntokens.MaxConsentResponseBytes)}
	if httpx.ReadStrictJSON(responseRequest, &out) != nil || out.Version != 1 || out.Profile != decisionProfile || out.Audience != profile.Audience || out.Subject != subject || len(out.Results) != len(refs) || ctx.Err() != nil {
		return nil, errors.New("invalid authorization response")
	}
	for i, result := range out.Results {
		if result.Resource != refs[i] || result.Allowed && (result.Scope == nil || result.Scope.Validate() != nil) || !result.Allowed && result.Scope != nil {
			return nil, errors.New("invalid authorization result")
		}
	}
	return out.Results, nil
}
func effectiveAllows(c *authntokens.GrantConstraints, scope string, ref authntokens.ResourceRef) bool {
	return c != nil && slices.Contains(c.Scopes, scope) && slices.Contains(c.Namespaces, ref.Namespace) && (c.Selection.Mode == authntokens.CurrentAndFuture || slices.Contains(c.Selection.Resources, ref))
}
func useCredential(s *store.CredentialState) store.CredentialUse {
	g, x := &s.Grant, &s.Secret
	return store.CredentialUse{Hash: x.TokenHash, Purpose: x.Purpose, FormatVersion: 1, OwnerID: g.OwnerID, CallerID: g.CallerID, ProfileID: g.Constraints.ProfileID, ProfileRevision: g.Constraints.ProfileRevision, Audience: g.Constraints.Audience, Resource: x.Resource}
}
func credentialIdentity(s *store.CredentialState) *caller.Identity {
	g := &s.Grant
	kind := g.Kind
	if s.Secret.Purpose == store.SecretExchange || s.Secret.Purpose == store.SecretDiscovery || s.Secret.Purpose == store.SecretResource {
		kind = caller.DelegationProof
	}
	id := &caller.Identity{Version: 1, CallerKind: s.CallerKind, CallerID: g.CallerID.String(), OwnerSubject: g.OwnerID.String(), EffectiveSubject: g.OwnerID.String(), CredentialKind: kind, CredentialID: g.ID.String(), Assurance: caller.Verified}
	if g.ClientBinding != nil {
		id.ClientID = g.ClientBinding.ClientID
		id.ConnectionID = g.ID.String()
	}
	return id
}

func (u *credentialIssuer) bound(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		fn(w, r.WithContext(ctx))
	}
}
