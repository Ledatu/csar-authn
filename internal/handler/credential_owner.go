package handler

import (
	"github.com/ledatu/csar-authn/internal/store"
	csarerrors "github.com/ledatu/csar-core/errors"
	"github.com/ledatu/csar-core/httpx"
	"net/http"
)

func (h *Handler) directCredentialOwner(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	// Owner-issued credentials require the owner’s direct browser session.
	if r.Header.Get("Authorization") != "" {
		httpx.WriteError(w, csarerrors.Unauthorized("session required"))
		return nil, false
	}
	sess, user, ok := h.authenticateRequest(w, r)
	if !ok || sess == nil {
		if ok {
			httpx.WriteError(w, csarerrors.Unauthorized("session required"))
		}
		return nil, false
	}
	if sess.ImpersonatorUserID != nil {
		httpx.WriteError(w, csarerrors.Forbidden("credentials require the owner session"))
		return nil, false
	}
	return user, true
}
