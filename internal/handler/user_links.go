package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/gatewayctx"
)

const (
	maxServiceUserLinkResolveIDs       = 1000
	maxServiceUserLinkResolveBodyBytes = 1 << 20
)

// serviceLinkResolvableProviders are the providers legacy Mongo identities are
// keyed by; anything wider turns the endpoint into a generic identity oracle.
var serviceLinkResolvableProviders = map[string]struct{}{
	"telegram": {},
	"yandex":   {},
}

type serviceUserLinkResolveRequest struct {
	Provider string   `json:"provider"`
	IDs      []string `json:"ids"`
}

type serviceUserLink struct {
	ProviderUserID string `json:"provider_user_id"`
	UserID         string `json:"user_id"`
}

type serviceUserLinkResolveResponse struct {
	Links []serviceUserLink `json:"links"`
}

func (h *Handler) handleResolveServiceUserLinks(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get(gatewayctx.HeaderSubject), "svc:") {
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "service identity required").Write(w)
		return
	}

	var req serviceUserLinkResolveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxServiceUserLinkResolveBodyBytes)).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	provider := strings.TrimSpace(strings.ToLower(req.Provider))
	if _, ok := serviceLinkResolvableProviders[provider]; !ok {
		apierror.New("bad_request", http.StatusBadRequest, "unsupported provider").Write(w)
		return
	}
	if len(req.IDs) > maxServiceUserLinkResolveIDs {
		apierror.New("bad_request", http.StatusBadRequest,
			fmt.Sprintf("at most %d ids per request", maxServiceUserLinkResolveIDs)).Write(w)
		return
	}

	links := []serviceUserLink{}
	if ids := dedupeProviderUserIDs(req.IDs); len(ids) > 0 {
		users, err := h.store.GetUsersByProviderIDs(r.Context(), provider, ids)
		if err != nil {
			h.logger.Error("failed to resolve service user links", "provider", provider, "error", err)
			apierror.New("internal_error", http.StatusInternalServerError, "failed to resolve users").Write(w)
			return
		}
		for _, u := range users {
			links = append(links, serviceUserLink{ProviderUserID: u.ProviderUserID, UserID: u.ID.String()})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(serviceUserLinkResolveResponse{Links: links})
}
