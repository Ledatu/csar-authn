package handler

import (
	"errors"
	"net/http"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/httpx"
)

// requestInfo renders only the issuer's browser-bound snapshot. URL query
// labels are not authoritative and never become consent identity.
func (o *sellerOAuth) requestInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := o.directCredentialOwner(w, r); !ok {
		return
	}
	cookie, err := r.Cookie(consentCookie)
	if err != nil || len(cookie.Value) != 43 || len(r.PathValue("id")) != 43 {
		oauthError(w, 400, "invalid_request")
		return
	}
	requests, ok := o.grants.(store.MCPRequestInfoStore)
	if !ok {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	info, err := requests.MCPRequestInfo(r.Context(), r.PathValue("id"), hashValue(cookie.Value))
	if errors.Is(err, store.ErrNotFound) {
		oauthError(w, 400, "invalid_request")
		return
	}
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	httpx.WriteJSON(w, 200, info)
}
