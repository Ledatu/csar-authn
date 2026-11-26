package handler

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
)

type credentialConsentInput struct {
	ProfileID  string                        `json:"profile_id"`
	Scopes     []string                      `json:"scopes"`
	Namespaces []string                      `json:"namespaces"`
	Selection  authntokens.ResourceSelection `json:"selection"`
}

func (in *credentialConsentInput) constraints(p *authnconfig.CredentialProfile) (authntokens.GrantConstraints, error) {
	g := authntokens.GrantConstraints{Version: 1, ProfileID: in.ProfileID, Scopes: in.Scopes, Namespaces: in.Namespaces, Selection: in.Selection}
	if p == nil {
		return g, store.ErrCredentialInvalid
	}
	g.ProfileRevision = p.Revision
	g.Audience = p.Audience
	effective, err := p.Narrow(&g)
	if err != nil || len(effective.Scopes) != len(g.Scopes) || len(effective.Namespaces) != len(g.Namespaces) || len(effective.Selection.Resources) != len(g.Selection.Resources) {
		return g, store.ErrCredentialInvalid
	}
	return g, nil
}
func (u *credentialIssuer) checkSelection(r *http.Request, p *authnconfig.CredentialProfile, owner string, g *authntokens.GrantConstraints) error {
	if g.Selection.Mode == authntokens.CurrentAndFuture {
		return nil
	} // consent only; each actual resource still requires a live decision
	for _, scope := range g.Scopes {
		for start := 0; start < len(g.Selection.Resources); start += authntokens.MaxDecisionResources {
			end := min(start+authntokens.MaxDecisionResources, len(g.Selection.Resources))
			results, err := u.decide(r.Context(), p, owner, scope, g.Selection.Resources[start:end])
			if err != nil {
				return err
			}
			for _, v := range results {
				if !v.Allowed {
					return store.ErrCredentialInvalid
				}
			}
		}
	}
	return nil
}
func (u *credentialIssuer) create(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, true)
	if !ok {
		return
	}
	var in struct {
		credentialConsentInput
		credentialCallerInput
		Label      string                `json:"label"`
		Kind       caller.CredentialKind `json:"kind"`
		TTLSeconds *int64                `json:"ttl_seconds,omitempty"`
	}
	if !credentialJSONLimit(w, r, &in, authntokens.MaxConsentResponseBytes) {
		return
	}
	p := u.profile(in.ProfileID)
	constraints, err := in.constraints(p)
	if err != nil {
		credentialError(w, 400)
		return
	}
	// Kind is a compatibility assertion only. The trusted profile fixes the
	// immutable cap family; omitting a client cannot add OAuth/refresh authority.
	kind := caller.APIKey
	ttl := min(p.GrantTTL.Duration, p.AccessTTL.Duration)
	minimum := time.Second
	if m := p.ManualIssuance; m != nil {
		ttl = m.MaxTTL.Duration
		if m.Family == "connection" {
			kind = caller.OAuthAccess
			minimum = time.Hour
		}
	}
	if in.Kind != "" && in.Kind != kind {
		credentialError(w, 400)
		return
	}
	if in.TTLSeconds != nil {
		if *in.TTLSeconds < int64(minimum/time.Second) || *in.TTLSeconds > int64(ttl/time.Second) {
			credentialError(w, 400)
			return
		}
		ttl = time.Duration(*in.TTLSeconds) * time.Second
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
	g := store.CredentialGrant{ID: uuid.New(), SchemaVersion: 1, OwnerID: owner.ID, CallerID: cid, Kind: kind, Constraints: constraints, Label: in.Label, ExpiresAt: time.Now().Add(ttl)}
	raw, x := genericToken(store.SecretAccess)
	x.ID = uuid.New()
	x.GrantID = g.ID
	x.ExpiresAt = g.ExpiresAt
	if err := u.store.CreateCredentialGrant(r.Context(), &g, []store.CredentialSecret{x}, fresh); err != nil {
		credentialError(w, 409)
		return
	}
	httpx.WriteJSON(w, 201, map[string]any{"id": g.ID, "token": raw, "token_type": "Bearer", "expires_at": x.ExpiresAt, "grant_expires_at": g.ExpiresAt, "constraints": constraints})
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (u *credentialIssuer) list(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, false)
	if !ok {
		return
	}
	if r.URL.Query().Has("view") {
		u.listConsent(w, r, owner.ID)
		return
	}
	grants, err := u.store.ListCredentialGrants(r.Context(), owner.ID)
	if err != nil {
		credentialError(w, 503)
		return
	}
	type item struct {
		ID              uuid.UUID                 `json:"id"`
		CallerID        uuid.UUID                 `json:"caller_id"`
		Kind            caller.CredentialKind     `json:"kind"`
		Label           string                    `json:"label"`
		ProfileID       string                    `json:"profile_id"`
		ProfileRevision uint64                    `json:"profile_revision"`
		ScopeCount      int                       `json:"scope_count"`
		NamespaceCount  int                       `json:"namespace_count"`
		SelectionMode   authntokens.SelectionMode `json:"selection_mode"`
		SelectedCount   int                       `json:"selected_resource_count"`
		ExpiresAt       time.Time                 `json:"expires_at"`
		Compatible      bool                      `json:"compatible"`
	}
	items := make([]item, 0, len(grants))
	for _, g := range grants {
		_, err := u.profile(g.Constraints.ProfileID).Narrow(&g.Constraints)
		items = append(items, item{g.ID, g.CallerID, g.Kind, g.Label, g.Constraints.ProfileID, g.Constraints.ProfileRevision, len(g.Constraints.Scopes), len(g.Constraints.Namespaces), g.Constraints.Selection.Mode, len(g.Constraints.Selection.Resources), g.ExpiresAt, err == nil})
	}
	httpx.WriteJSON(w, 200, map[string]any{"items": items})
}
func (u *credentialIssuer) detail(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, false)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("grant_id"))
	if err != nil || id == uuid.Nil {
		credentialError(w, 400)
		return
	}
	g, err := u.store.GetCredentialGrant(r.Context(), owner.ID, id)
	if err != nil {
		credentialError(w, 404)
		return
	}
	_, err = u.profile(g.Constraints.ProfileID).Narrow(&g.Constraints)
	httpx.WriteJSON(w, 200, map[string]any{"id": g.ID, "caller_id": g.CallerID, "kind": g.Kind, "label": g.Label, "constraints": g.Constraints, "created_at": g.CreatedAt, "expires_at": g.ExpiresAt, "last_used_at": g.LastUsedAt, "compatible": err == nil})
}

func (u *credentialIssuer) revoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := u.owner(w, r, true)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("grant_id"))
	if err != nil || id == uuid.Nil {
		credentialError(w, 400)
		return
	}
	if err := u.store.RevokeCredentialGrant(r.Context(), owner.ID, id); err != nil {
		credentialError(w, 404)
		return
	}
	w.WriteHeader(204)
}

func consentContains(c *authntokens.GrantConstraints, scope, namespace string) bool {
	return c != nil && slices.Contains(c.Scopes, scope) && slices.Contains(c.Namespaces, namespace)
}
