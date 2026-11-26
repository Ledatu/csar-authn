package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
)

type credentialProofBinding struct {
	Namespace string `json:"namespace"`
	Scope     string `json:"scope"`
}

// The complete opaque value (including this public operation binding) is hashed.
// Metadata is not trusted until that exact hash resolves to the immutable secret.
func genericProof(p store.SecretPurpose, namespace, scope string) (string, store.CredentialSecret) {
	binding, _ := json.Marshal(credentialProofBinding{namespace, scope})
	raw := "csar_v1_" + string(p) + "." + base64.RawURLEncoding.EncodeToString(binding) + "." + randomToken()
	return raw, store.CredentialSecret{Purpose: p, FormatVersion: 1, TokenHash: hashValue(raw)}
}
func proofBinding(raw string) (credentialProofBinding, bool) {
	var b credentialProofBinding
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[1]) > 2048 || !validGenericEntropy(parts[2]) {
		return b, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != parts[1] || store.DecodeCredentialJSON(data, &b) != nil || !authntokens.ValidNamespace(b.Namespace) || !authntokens.ValidScope(b.Scope) {
		return b, false
	}
	return b, true
}
func validGenericEntropy(s string) bool {
	if len(s) != 43 {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
func (u *credentialIssuer) introspect(w http.ResponseWriter, r *http.Request) {
	var in authntokens.DelegationRequestV2
	if !credentialJSON(w, r, &in) {
		return
	}
	p := u.profile(in.ProfileID)
	if p == nil || !u.trusted(r, p.TrustPolicy) {
		credentialError(w, 403)
		return
	}
	inactive := func() { httpx.WriteJSON(w, 200, authntokens.DelegationResultV2{Version: 2}) }
	if in.Validate() != nil {
		inactive()
		return
	}
	purpose := store.SecretAccess
	switch in.Purpose {
	case authntokens.GrantDiscovery:
		purpose = store.SecretDiscovery
	case authntokens.GrantResource:
		purpose = store.SecretResource
	}
	state, profile, effective, err := u.state(r.Context(), in.Token, purpose)
	if err != nil {
		if err == store.ErrNotFound || err == store.ErrCredentialInvalid {
			inactive()
		} else {
			credentialError(w, 503)
		}
		return
	}
	if profile.ID != in.ProfileID || in.Audience != profile.Audience || !consentContains(effective, in.Scope, in.Namespace) {
		inactive()
		return
	}
	if purpose != store.SecretAccess {
		b, ok := proofBinding(in.Token)
		if !ok || b.Scope != in.Scope || b.Namespace != in.Namespace {
			inactive()
			return
		}
	}
	out := authntokens.DelegationResultV2{Version: 2, Active: true, Purpose: in.Purpose, ProfileID: profile.ID, ProfileRevision: state.Grant.Constraints.ProfileRevision, Audience: profile.Audience, Scope: in.Scope, Namespace: in.Namespace, Resource: in.Resource, Identity: credentialIdentity(&state), ExpiresAt: minTime(state.Grant.ExpiresAt, state.Secret.ExpiresAt)}
	var children []store.CredentialSecret
	switch purpose {
	case store.SecretAccess:
		if in.Purpose == authntokens.AccessResource {
			break
		}
		raw, proof := genericProof(store.SecretDiscovery, in.Namespace, in.Scope)
		proof.ID = uuid.New()
		proof.GrantID = state.Grant.ID
		proof.ExpiresAt = minTime(out.ExpiresAt, time.Now().Add(profile.ProofTTL.Duration))
		children = []store.CredentialSecret{proof}
		out.DelegatedToken = raw
		out.ExpiresAt = proof.ExpiresAt
	case store.SecretResource:
		if state.Secret.Resource == nil || *state.Secret.Resource != *in.Resource || !effectiveAllows(effective, in.Scope, *in.Resource) {
			inactive()
			return
		}
	}
	if in.Purpose == authntokens.GrantResource || in.Purpose == authntokens.AccessResource {
		if in.Resource == nil || !effectiveAllows(effective, in.Scope, *in.Resource) {
			inactive()
			return
		}
		decisions, err := u.decide(r.Context(), profile, state.Grant.OwnerID.String(), in.Scope, []authntokens.ResourceRef{*in.Resource})
		if err != nil {
			credentialError(w, 503)
			return
		}
		if !decisions[0].Allowed {
			inactive()
			return
		}
		out.AuthorizedScope = decisions[0].Scope
	}
	if out.ValidateFor(&in, time.Now()) != nil {
		credentialError(w, 503)
		return
	}
	setAuthenticatedContext(r, &store.User{ID: state.Grant.OwnerID}, credentialIdentity(&state))
	var useErr error
	if in.Purpose == authntokens.AccessResource {
		_, useErr = u.store.UseCredentialAccess(r.Context(), useCredential(&state), in.Scope, *in.Resource)
	} else {
		_, useErr = u.store.ExchangeCredentialSecret(r.Context(), useCredential(&state), children)
	}
	if useErr != nil {
		if !errors.Is(useErr, store.ErrNotFound) && !errors.Is(useErr, store.ErrCredentialInvalid) && !errors.Is(useErr, store.ErrCredentialReplay) {
			credentialError(w, 503)
			return
		}
		inactive()
		return
	}
	httpx.WriteJSON(w, 200, out)
}

type credentialInspectRequest struct {
	Version   int       `json:"version"`
	ProfileID string    `json:"profile_id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	GrantID   uuid.UUID `json:"grant_id"`
	Scope     string    `json:"scope"`
}

func (u *credentialIssuer) serviceGrant(w http.ResponseWriter, r *http.Request, in *credentialInspectRequest, op string) (store.CredentialGrant, *authnconfig.CredentialProfile, *authntokens.GrantConstraints, time.Time, bool) {
	fail := func() (store.CredentialGrant, *authnconfig.CredentialProfile, *authntokens.GrantConstraints, time.Time, bool) {
		credentialError(w, 403)
		return store.CredentialGrant{}, nil, nil, time.Time{}, false
	}
	if in.Version != 2 || in.OwnerID == uuid.Nil || in.GrantID == uuid.Nil || !authntokens.ValidScope(in.Scope) {
		return fail()
	}
	id, err := gatewayctx.FromRequestChecked(r)
	if err != nil || id.Caller == nil || id.Caller.ValidateBinding(id.Subject, id.CredentialID) != nil || id.Caller.CallerKind != caller.Service || id.Caller.CredentialKind != caller.STS || id.Caller.CallerID != id.Subject || id.Origin == nil || id.Origin.Caller == nil || !time.Now().Before(id.Origin.ExpiresAt) {
		return fail()
	}
	original := id.Origin.Caller
	account := id.Origin.Account
	if account == nil || account.Kind != "credential" || account.Validate(original) != nil || account.ProfileID != in.ProfileID {
		return fail()
	}
	if original.Validate() != nil || (original.CredentialKind != caller.APIKey && original.CredentialKind != caller.OAuthAccess && original.CredentialKind != caller.DelegationProof) || (original.CallerKind != caller.Agent && original.CallerKind != caller.Application) || original.OwnerSubject != in.OwnerID.String() || original.EffectiveSubject != in.OwnerID.String() || original.CredentialID != in.GrantID.String() {
		return fail()
	}
	permitted := false
	for _, receiver := range u.cfg.Receivers {
		if receiver.Subject == id.Subject && slices.Contains(receiver.Profiles, in.ProfileID) && slices.Contains(receiver.Operations, op) && u.trusted(r, receiver.TrustPolicy) {
			permitted = true
		}
	}
	p := u.profile(in.ProfileID)
	if !permitted || p == nil {
		return fail()
	}
	g, err := u.store.GetCredentialGrant(r.Context(), in.OwnerID, in.GrantID)
	if err != nil {
		if err == store.ErrNotFound {
			return fail()
		}
		credentialError(w, 503)
		return store.CredentialGrant{}, nil, nil, time.Time{}, false
	}
	effective, err := p.Narrow(&g.Constraints)
	if err != nil || account.ProfileRevision != g.Constraints.ProfileRevision || account.Audience != g.Constraints.Audience || !slices.Contains(effective.Scopes, in.Scope) || g.CallerID.String() != original.CallerID {
		return fail()
	}
	if original.CredentialKind != caller.DelegationProof && original.CredentialKind != g.Kind {
		return fail()
	}
	*r = *r.WithContext(gatewayctx.NewContext(r.Context(), &id))
	return g, p, effective, minTime(g.ExpiresAt, id.Origin.ExpiresAt), true
}
func (u *credentialIssuer) inspect(w http.ResponseWriter, r *http.Request) {
	var in credentialInspectRequest
	if !credentialJSON(w, r, &in) {
		return
	}
	_, _, effective, expires, ok := u.serviceGrant(w, r, &in, "inspect")
	if !ok {
		return
	}
	// Consent metadata only. Receivers must evaluate current resource authority;
	// an all-future selector or listed reference is never a current permission.
	httpx.WriteJSON(w, 200, map[string]any{"version": 2, "grant_id": in.GrantID, "owner_id": in.OwnerID, "constraints": effective, "expires_at": expires, "consent_only": true})
}
func (u *credentialIssuer) evaluate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		credentialInspectRequest
		Resources  []authntokens.ResourceRef `json:"resources"`
		IssueProof bool                      `json:"issue_proof"`
	}
	if !credentialJSON(w, r, &in) {
		return
	}
	if authntokens.ValidateResources(in.Resources, authntokens.MaxDecisionResources) != nil || in.IssueProof && len(in.Resources) != 1 {
		credentialError(w, 400)
		return
	}
	g, p, effective, expires, ok := u.serviceGrant(w, r, &in.credentialInspectRequest, "evaluate")
	if !ok {
		return
	}
	results := make([]credentialDecision, len(in.Resources))
	var eligible []authntokens.ResourceRef
	var positions []int
	for i, ref := range in.Resources {
		results[i].Resource = ref
		if effectiveAllows(effective, in.Scope, ref) {
			eligible = append(eligible, ref)
			positions = append(positions, i)
		}
	}
	if len(eligible) > 0 {
		decisions, err := u.decide(r.Context(), p, g.OwnerID.String(), in.Scope, eligible)
		if err != nil {
			credentialError(w, 503)
			return
		}
		for i, index := range positions {
			results[index] = decisions[i]
		}
	}
	var raw string
	if in.IssueProof && results[0].Allowed {
		var proof store.CredentialSecret
		raw, proof = genericProof(store.SecretResource, in.Resources[0].Namespace, in.Scope)
		proof.ID = uuid.New()
		proof.GrantID = g.ID
		proof.Resource = &in.Resources[0]
		proof.ExpiresAt = minTime(expires, time.Now().Add(p.ProofTTL.Duration))
		expires = proof.ExpiresAt
		if err := u.store.IssueCredentialResource(r.Context(), g.OwnerID, g.ID, proof); err != nil {
			credentialError(w, 503)
			return
		}
	}
	if r.Context().Err() != nil {
		credentialError(w, 503)
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"version": 2, "grant_id": g.ID, "owner_id": g.OwnerID, "scope": in.Scope, "results": results, "proof": raw, "expires_at": expires})
}
