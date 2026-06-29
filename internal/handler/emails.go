package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
)

type deleteEmailRequest struct {
	Email string `json:"email"`
}

func (h *Handler) handleDeleteMeEmail(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	var req deleteEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}
	email, err := store.NormalizeEmailString(req.Email)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid email").Write(w)
		return
	}

	if err := h.store.DeleteEmailOAuthAccount(r.Context(), user.ID, email); err != nil {
		if errors.Is(err, store.ErrLastLoginMethod) {
			apierror.New("bad_request", http.StatusBadRequest, "cannot remove the last login method").Write(w)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "email not found").Write(w)
			return
		}
		h.logger.Error("failed to unlink email", "user_id", user.ID, "email", email, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to unlink email").Write(w)
		return
	}

	h.recordAudit(r, user.ID.String(), "email.disconnect", "email", email, nil)
	w.WriteHeader(http.StatusNoContent)
}
