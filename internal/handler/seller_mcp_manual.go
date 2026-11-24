package handler

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/httpx"
)

func (o *sellerOAuth) createManualToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !o.checkAPIKeyMutationOrigin(w, r) {
		return
	}
	u, ok := o.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	var in struct {
		store.MCPSelection
		credentialCallerInput
		Hours int `json:"hours"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if httpx.ReadJSON(r, &in) != nil || in.Hours < 1 || in.Hours > 24*store.MCPConnectionDays {
		oauthError(w, 400, "invalid_request")
		return
	}
	if !o.validateMCPSelection(w, r, u.ID, &in.MCPSelection) {
		return
	}
	fresh, err := in.newCaller(u.ID, "Приложение")
	if err != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	tokens, ok := o.grants.(store.MCPManualTokenStore)
	if !ok {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	raw := "aurum_mcp_" + randomToken()
	g, err := tokens.CreateManualMCP(r.Context(), store.MCPManualToken{OwnerID: u.ID, CallerID: in.CallerID, NewCaller: fresh, Selection: in.MCPSelection, AccessHash: hashValue(raw), Hours: in.Hours})
	switch {
	case errors.Is(err, store.ErrCallerLimit), errors.Is(err, store.ErrMCPConnectionLimit):
		oauthError(w, 409, "connection_limit_reached")
	case errors.Is(err, store.ErrNotFound):
		oauthError(w, 400, "invalid_request")
	case err != nil:
		oauthError(w, 503, "temporarily_unavailable")
	default:
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{"access_token": raw, "token_type": "Bearer", "scope": store.APIKeyScopeAnalyticsRead, "expires_in": int(time.Until(g.ExpiresAt).Seconds()), "expires_at": g.ExpiresAt, "grant_id": g.ID})
	}
}

// Owner consent is separate from permission at use. Both OAuth and manual
// issuance verify current selected-store permissions; all-store grants remain
// filtered by current access on every discovery/report request.
func (o *sellerOAuth) validateMCPSelection(w http.ResponseWriter, r *http.Request, owner uuid.UUID, in *store.MCPSelection) bool {
	if len(in.SellerIDs) > 256 || in.AllCampaigns != (len(in.SellerIDs) == 0) {
		oauthError(w, 400, "invalid_request")
		return false
	}
	slices.Sort(in.SellerIDs)
	for i, seller := range in.SellerIDs {
		if !validWBSellerID(seller) || i > 0 && seller == in.SellerIDs[i-1] {
			oauthError(w, 400, "invalid_request")
			return false
		}
		if !o.allowSellerScopes(w, r, owner, seller, []string{store.APIKeyScopeAnalyticsRead}) {
			return false
		}
	}
	return true
}
