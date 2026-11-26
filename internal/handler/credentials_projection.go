package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
)

type consentListItem struct {
	ID          uuid.UUID                    `json:"id"`
	CallerID    uuid.UUID                    `json:"caller_id"`
	Kind        caller.CredentialKind        `json:"kind"`
	CallerKind  caller.Kind                  `json:"caller_kind"`
	CallerLabel string                       `json:"caller_label"`
	Label       string                       `json:"label"`
	ClientID    string                       `json:"client_id,omitempty"`
	ClientName  string                       `json:"client_name,omitempty"`
	Constraints authntokens.GrantConstraints `json:"constraints"`
	CreatedAt   time.Time                    `json:"created_at"`
	ExpiresAt   time.Time                    `json:"expires_at"`
	LastUsedAt  *time.Time                   `json:"last_used_at"`
	Compatible  bool                         `json:"compatible"`
}

// This owner-only projection avoids one detail HTTP call per connection. Five
// complete original consent snapshots fit its bounded response; no secret or
// current resource-authorization claim is included.
func (u *credentialIssuer) listConsent(w http.ResponseWriter, r *http.Request, owner uuid.UUID) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 4096 || !uniqueParams(q) || q.Get("view") != "consent" {
		credentialError(w, http.StatusBadRequest)
		return
	}
	for key := range q {
		if !slices.Contains([]string{"view", "kind", "profiles", "offset", "limit"}, key) {
			credentialError(w, http.StatusBadRequest)
			return
		}
	}
	kind := caller.CredentialKind(q.Get("kind"))
	if kind != "" && kind != caller.APIKey && kind != caller.OAuthAccess {
		credentialError(w, http.StatusBadRequest)
		return
	}
	var profiles []string
	if q.Has("profiles") {
		profiles = strings.Split(q.Get("profiles"), ",")
		if len(profiles) > 32 {
			credentialError(w, http.StatusBadRequest)
			return
		}
		for i, id := range profiles {
			if !authntokens.ValidProfileID(id) || slices.Contains(profiles[:i], id) {
				credentialError(w, http.StatusBadRequest)
				return
			}
		}
	}
	limit, offset := 5, 0
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 5 {
			credentialError(w, http.StatusBadRequest)
			return
		}
	}
	if q.Has("offset") {
		offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil || offset < 0 || offset > store.CredentialAPIKeyLimit+store.CredentialOAuthLimit {
			credentialError(w, http.StatusBadRequest)
			return
		}
	}
	capacityStore, ok := u.store.(store.CredentialCapacityReader)
	if !ok {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	registry, ok := u.h.store.(store.CallerRegistryStore)
	if !ok {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	capacity, err := capacityStore.CredentialCapacity(r.Context(), owner)
	if err != nil {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	grants, err := u.store.ListCredentialGrants(r.Context(), owner)
	if err != nil {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	registered, err := registry.ListActiveCallers(r.Context(), owner)
	if err != nil {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	callers := make(map[uuid.UUID]store.Caller, len(registered))
	for _, c := range registered {
		callers[c.ID] = c
	}
	filtered := make([]store.CredentialGrant, 0, len(grants))
	for i := range grants {
		g := &grants[i]
		if (kind == "" || kind == g.Kind) && (len(profiles) == 0 || slices.Contains(profiles, g.Constraints.ProfileID)) {
			filtered = append(filtered, *g)
		}
	}
	items := []consentListItem{}
	for i := min(offset, len(filtered)); i < min(offset+limit, len(filtered)); i++ {
		g := &filtered[i]
		registered, ok := callers[g.CallerID]
		if !ok || registered.OwnerID != owner || registered.RevokedAt != nil || registered.ValidateRegistration() != nil {
			credentialError(w, http.StatusServiceUnavailable)
			return
		}
		_, compatible := u.profile(g.Constraints.ProfileID).Narrow(&g.Constraints)
		item := consentListItem{ID: g.ID, CallerID: g.CallerID, Kind: g.Kind, CallerKind: registered.Kind, CallerLabel: registered.Label, Label: g.Label, Constraints: g.Constraints, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt, LastUsedAt: g.LastUsedAt, Compatible: compatible == nil}
		if g.ClientBinding != nil {
			item.ClientID = g.ClientBinding.ClientID
			item.ClientName = g.ClientBinding.ClientName
		}
		items = append(items, item)
	}
	type capacityItem struct {
		Active int `json:"active"`
		Limit  int `json:"limit"`
	}
	out := struct {
		Version     int                     `json:"version"`
		ConsentOnly bool                    `json:"consent_only"`
		Items       []consentListItem       `json:"items"`
		Next        *int                    `json:"next_offset,omitempty"`
		Capacity    map[string]capacityItem `json:"capacity"`
	}{Version: 1, ConsentOnly: true, Items: items, Capacity: map[string]capacityItem{"api_key": {capacity.APIKeys, store.CredentialAPIKeyLimit}, "oauth_access": {capacity.Connections, store.CredentialOAuthLimit}}}
	if next := offset + len(items); next < len(filtered) && len(items) > 0 {
		out.Next = &next
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > 1<<20 || r.Context().Err() != nil {
		credentialError(w, http.StatusServiceUnavailable)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, json.RawMessage(encoded))
}
