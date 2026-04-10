package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ledatu/csar-authn/internal/avatar"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

const (
	maxProfileDisplayNameLen = 120
	maxAvatarUploadBytes     = 10 << 20
)

var allowedAvatarContentTypes = map[string]struct{}{
	"image/gif":  {},
	"image/jpeg": {},
	"image/png":  {},
	"image/webp": {},
}

type avatarService interface {
	CreateUploadIntent(ctx context.Context, req avatar.UploadIntentRequest) (*avatar.UploadIntentResponse, error)
	FinalizeAvatar(ctx context.Context, req avatar.FinalizeAvatarRequest) (*avatar.FinalizeAvatarResponse, error)
	DeleteObject(ctx context.Context, storageKey string) error
	SignedReadURL(ctx context.Context, storageKey string) (string, error)
}

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
	AvatarURL   string `json:"avatar_url,omitempty"`
}

type avatarUploadIntentRequest struct {
	ContentType   string `json:"content_type"`
	ContentLength int64  `json:"content_length"`
	Filename      string `json:"filename,omitempty"`
}

type avatarUploadIntentResponse struct {
	UploadToken string            `json:"upload_token"`
	ObjectKey   string            `json:"object_key,omitempty"`
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type finalizeAvatarRequest struct {
	UploadToken string `json:"upload_token"`
}

func (h *Handler) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	var req updateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	httpx.WriteJSON(w, http.StatusOK, h.buildProfileResponse(r.Context(), user))
}

func (h *Handler) handleAvatarUploadIntent(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	if h.avatarClient == nil {
		apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
		return
	}

	var req avatarUploadIntentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	contentType := strings.TrimSpace(strings.ToLower(req.ContentType))
	if _, ok := allowedAvatarContentTypes[contentType]; !ok {
		apierror.New("bad_request", http.StatusBadRequest, "unsupported avatar content_type").Write(w)
		return
	}
	if req.ContentLength <= 0 || req.ContentLength > maxAvatarUploadBytes {
		apierror.New("bad_request", http.StatusBadRequest, "content_length is out of bounds").Write(w)
		return
	}

	intent, err := h.avatarClient.CreateUploadIntent(r.Context(), avatar.UploadIntentRequest{
		UserID:        user.ID.String(),
		ContentType:   contentType,
		ContentLength: req.ContentLength,
		Filename:      strings.TrimSpace(req.Filename),
	})
	if err != nil {
		h.logger.Error("failed to create avatar upload intent", "user_id", user.ID, "error", err)
		apierror.New("bad_gateway", http.StatusBadGateway, "failed to create avatar upload intent").Write(w)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, avatarUploadIntentResponse{
		UploadToken: intent.UploadToken,
		ObjectKey:   intent.ObjectKey,
		Method:      intent.Method,
		URL:         intent.URL,
		Headers:     intent.Headers,
	})
}

func (h *Handler) handleFinalizeAvatar(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	if h.avatarClient == nil {
		apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
		return
	}

	var req finalizeAvatarRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}
	if strings.TrimSpace(req.UploadToken) == "" {
		apierror.New("bad_request", http.StatusBadRequest, "upload_token is required").Write(w)
		return
	}

	finalized, err := h.avatarClient.FinalizeAvatar(r.Context(), avatar.FinalizeAvatarRequest{
		UserID:      user.ID.String(),
		UploadToken: strings.TrimSpace(req.UploadToken),
	})
	if err != nil {
		h.logger.Error("failed to finalize avatar", "user_id", user.ID, "error", err)
		apierror.New("bad_gateway", http.StatusBadGateway, "failed to finalize avatar").Write(w)
		return
	}
	if strings.TrimSpace(finalized.StorageKey) == "" {
		apierror.New("bad_gateway", http.StatusBadGateway, "avatar service returned no storage key").Write(w)
		return
	}
	if finalized.ContentType != "" {
		if _, ok := allowedAvatarContentTypes[strings.ToLower(finalized.ContentType)]; !ok {
			apierror.New("bad_gateway", http.StatusBadGateway, "avatar service returned unsupported content type").Write(w)
			return
		}
	}

	previousKey := user.AvatarStorageKey
	if err := h.store.UpdateUserAvatar(r.Context(), user.ID, finalized.StorageKey); err != nil {
		h.logger.Error("failed to persist avatar storage key", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to save avatar").Write(w)
		return
	}
	user.AvatarStorageKey = finalized.StorageKey
	user.AvatarURL = ""

	if previousKey != "" && previousKey != finalized.StorageKey {
		if err := h.avatarClient.DeleteObject(r.Context(), previousKey); err != nil {
			h.logger.Warn("failed to delete previous avatar", "user_id", user.ID, "storage_key", previousKey, "error", err)
		}
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"avatar_storage_key": finalized.StorageKey,
	})
	h.recordAudit(r, user.ID.String(), "user.avatar.update", "user", user.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, h.buildProfileResponse(r.Context(), user))
}

func (h *Handler) handleDeleteAvatar(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	if user.AvatarStorageKey != "" {
		if h.avatarClient == nil {
			apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
			return
		}
		if err := h.avatarClient.DeleteObject(r.Context(), user.AvatarStorageKey); err != nil {
			h.logger.Error("failed to delete avatar object", "user_id", user.ID, "storage_key", user.AvatarStorageKey, "error", err)
			apierror.New("bad_gateway", http.StatusBadGateway, "failed to delete avatar").Write(w)
			return
		}
	}

	if err := h.store.UpdateUserAvatar(r.Context(), user.ID, ""); err != nil {
		h.logger.Error("failed to clear avatar", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to delete avatar").Write(w)
		return
	}
	user.AvatarStorageKey = ""
	user.AvatarURL = ""

	h.recordAudit(r, user.ID.String(), "user.avatar.delete", "user", user.ID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) buildProfileResponse(ctx context.Context, user *store.User) profileResponse {
	return profileResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		Phone:       user.Phone,
		DisplayName: user.DisplayName,
		AvatarURL:   h.resolveAvatarURL(ctx, user.AvatarStorageKey, user.AvatarURL),
	}
}

func (h *Handler) resolveAvatarURL(ctx context.Context, avatarStorageKey, legacyURL string) string {
	if strings.TrimSpace(avatarStorageKey) == "" {
		return legacyURL
	}
	if h.avatarClient == nil {
		return legacyURL
	}
	url, err := h.avatarClient.SignedReadURL(ctx, avatarStorageKey)
	if err != nil {
		h.logger.Warn("failed to resolve avatar url", "storage_key", avatarStorageKey, "error", err)
		return legacyURL
	}
	return url
}
