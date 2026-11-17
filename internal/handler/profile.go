package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

const maxProfileDisplayNameLen = 120

type updateProfileRequest struct {
	DisplayName string  `json:"display_name"`
	Email       *string `json:"email,omitempty"`
	Phone       *string `json:"phone,omitempty"`
}

type profileResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	DisplayName string `json:"display_name"`
}

func (h *Handler) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	var req updateProfileRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}
	if req.Email != nil || req.Phone != nil {
		apierror.New("bad_request", http.StatusBadRequest, "email and phone are read-only").Write(w)
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	switch {
	case displayName == "":
		apierror.New("bad_request", http.StatusBadRequest, "display_name is required").Write(w)
		return
	case len([]rune(displayName)) > maxProfileDisplayNameLen:
		apierror.New("bad_request", http.StatusBadRequest, "display_name is too long").Write(w)
		return
	}

	if err := h.store.UpdateUserProfile(r.Context(), user.ID, displayName); err != nil {
		h.logger.Error("failed to update profile", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to update profile").Write(w)
		return
	}
	user.DisplayName = displayName

	afterJSON, _ := json.Marshal(map[string]any{
		"display_name": displayName,
	})
	h.recordAudit(r, user.ID.String(), "user.profile.update", "user", user.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, h.buildProfileResponse(user))
}

func (h *Handler) buildProfileResponse(user *store.User) profileResponse {
	return profileResponse{ID: user.ID.String(), Email: user.Email, Phone: user.Phone, DisplayName: user.DisplayName}
}
