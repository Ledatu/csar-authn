package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/avatar"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/jwtx"
)

const (
	maxProfileDisplayNameLen = 120
	maxAvatarUploadBytes     = 10 << 20

	avatarUploadSetAudience = "avatar-upload-set"
	avatarUploadSetTTL      = 15 * time.Minute

	managedAvatarContentType = "image/webp"

	avatarVariantPreview = "preview"
	avatarVariantDefault = "default"
	avatarVariantMaster  = "master"
)

var (
	allowedAvatarContentTypes = map[string]struct{}{
		"image/gif":  {},
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}
	managedAvatarVariantKinds = []string{
		avatarVariantPreview,
		avatarVariantDefault,
		avatarVariantMaster,
	}
)

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
	ID               string `json:"id"`
	Email            string `json:"email,omitempty"`
	Phone            string `json:"phone,omitempty"`
	DisplayName      string `json:"display_name"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	AvatarPreviewURL string `json:"avatar_preview_url,omitempty"`
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

type avatarUploadSetAssetRequest struct {
	Kind          string `json:"kind"`
	ContentType   string `json:"content_type"`
	ContentLength int64  `json:"content_length"`
	Filename      string `json:"filename,omitempty"`
}

type avatarUploadSetIntentRequest struct {
	Assets []avatarUploadSetAssetRequest `json:"assets"`
}

type avatarUploadSetIntentResponse struct {
	UploadToken string                                `json:"upload_token"`
	Assets      map[string]avatarUploadIntentResponse `json:"assets"`
}

type finalizeAvatarRequest struct {
	UploadToken string `json:"upload_token"`
}

type finalizeAvatarSetRequest struct {
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
	if err := validateAvatarUploadRequest(normalizeAvatarContentType(req.ContentType), req.ContentLength); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	}

	intent, err := h.createAvatarUploadIntent(r.Context(), user.ID.String(), req.ContentType, req.ContentLength, req.Filename)
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

func (h *Handler) handleAvatarUploadSetIntent(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	if h.avatarClient == nil {
		apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
		return
	}

	var req avatarUploadSetIntentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	assets, err := normalizeAvatarUploadSetRequest(req)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	}

	respAssets := make(map[string]avatarUploadIntentResponse, len(assets))
	intentIDs := make(map[string]string, len(assets))
	for _, kind := range managedAvatarVariantKinds {
		asset := assets[kind]
		intent, createErr := h.createAvatarUploadIntent(r.Context(), user.ID.String(), asset.ContentType, asset.ContentLength, asset.Filename)
		if createErr != nil {
			h.logger.Error("failed to create avatar upload intent", "user_id", user.ID, "kind", kind, "error", createErr)
			apierror.New("bad_gateway", http.StatusBadGateway, "failed to create avatar upload intent").Write(w)
			return
		}
		intentIDs[kind] = intent.UploadToken
		respAssets[kind] = avatarUploadIntentResponse{
			UploadToken: intent.UploadToken,
			ObjectKey:   intent.ObjectKey,
			Method:      intent.Method,
			URL:         intent.URL,
			Headers:     intent.Headers,
		}
	}

	uploadToken, err := h.issueAvatarUploadSetToken(user.ID.String(), intentIDs)
	if err != nil {
		h.logger.Error("failed to create avatar upload set token", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create avatar upload set").Write(w)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, avatarUploadSetIntentResponse{
		UploadToken: uploadToken,
		Assets:      respAssets,
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
	if err := validateFinalizedAvatar(finalized, false); err != nil {
		apierror.New("bad_gateway", http.StatusBadGateway, err.Error()).Write(w)
		return
	}

	previousKeys := managedAvatarKeysFromUser(user)
	nextAvatar := store.ManagedAvatar{
		DefaultStorageKey: finalized.StorageKey,
	}
	if err := h.store.UpdateUserAvatar(r.Context(), user.ID, nextAvatar); err != nil {
		h.logger.Error("failed to persist avatar storage key", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to save avatar").Write(w)
		return
	}
	user.AvatarStorageKey = finalized.StorageKey
	user.AvatarPreviewStorageKey = ""
	user.AvatarMasterStorageKey = ""
	user.AvatarURL = ""

	h.deleteAvatarKeys(r.Context(), user.ID.String(), keysToDelete(previousKeys, managedAvatarKeys(nextAvatar)))

	afterJSON, _ := json.Marshal(map[string]any{
		"avatar_storage_key": finalized.StorageKey,
	})
	h.recordAudit(r, user.ID.String(), "user.avatar.update", "user", user.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, h.buildProfileResponse(r.Context(), user))
}

func (h *Handler) handleFinalizeAvatarSet(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	if h.avatarClient == nil {
		apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
		return
	}

	var req finalizeAvatarSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}
	if strings.TrimSpace(req.UploadToken) == "" {
		apierror.New("bad_request", http.StatusBadRequest, "upload_token is required").Write(w)
		return
	}

	intentIDs, err := h.verifyAvatarUploadSetToken(strings.TrimSpace(req.UploadToken), user.ID.String())
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "upload_token is invalid").Write(w)
		return
	}

	finalizedKeys := make([]string, 0, len(intentIDs))
	finalizedByKind := make(map[string]*avatar.FinalizeAvatarResponse, len(intentIDs))
	for _, kind := range managedAvatarVariantKinds {
		finalized, finalizeErr := h.avatarClient.FinalizeAvatar(r.Context(), avatar.FinalizeAvatarRequest{
			UserID:      user.ID.String(),
			UploadToken: intentIDs[kind],
		})
		if finalizeErr != nil {
			h.deleteAvatarKeys(r.Context(), user.ID.String(), finalizedKeys)
			h.logger.Error("failed to finalize avatar variant", "user_id", user.ID, "kind", kind, "error", finalizeErr)
			apierror.New("bad_gateway", http.StatusBadGateway, "failed to finalize avatar").Write(w)
			return
		}
		if err := validateFinalizedAvatar(finalized, true); err != nil {
			h.deleteAvatarKeys(r.Context(), user.ID.String(), finalizedKeys)
			apierror.New("bad_gateway", http.StatusBadGateway, err.Error()).Write(w)
			return
		}
		finalizedByKind[kind] = finalized
		finalizedKeys = append(finalizedKeys, finalized.StorageKey)
	}

	nextAvatar := store.ManagedAvatar{
		DefaultStorageKey: finalizedByKind[avatarVariantDefault].StorageKey,
		PreviewStorageKey: finalizedByKind[avatarVariantPreview].StorageKey,
		MasterStorageKey:  finalizedByKind[avatarVariantMaster].StorageKey,
	}
	previousKeys := managedAvatarKeysFromUser(user)
	if err := h.store.UpdateUserAvatar(r.Context(), user.ID, nextAvatar); err != nil {
		h.deleteAvatarKeys(r.Context(), user.ID.String(), finalizedKeys)
		h.logger.Error("failed to persist avatar storage keys", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to save avatar").Write(w)
		return
	}

	user.AvatarStorageKey = nextAvatar.DefaultStorageKey
	user.AvatarPreviewStorageKey = nextAvatar.PreviewStorageKey
	user.AvatarMasterStorageKey = nextAvatar.MasterStorageKey
	user.AvatarURL = ""

	h.deleteAvatarKeys(r.Context(), user.ID.String(), keysToDelete(previousKeys, managedAvatarKeys(nextAvatar)))

	afterJSON, _ := json.Marshal(map[string]any{
		"avatar_storage_key":         nextAvatar.DefaultStorageKey,
		"avatar_preview_storage_key": nextAvatar.PreviewStorageKey,
		"avatar_master_storage_key":  nextAvatar.MasterStorageKey,
	})
	h.recordAudit(r, user.ID.String(), "user.avatar.update", "user", user.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, h.buildProfileResponse(r.Context(), user))
}

func (h *Handler) handleDeleteAvatar(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	keys := managedAvatarKeysFromUser(user)
	if len(keys) > 0 {
		if h.avatarClient == nil {
			apierror.New("service_unavailable", http.StatusServiceUnavailable, "avatar storage is not configured").Write(w)
			return
		}
		for _, key := range keys {
			if err := h.avatarClient.DeleteObject(r.Context(), key); err != nil {
				h.logger.Error("failed to delete avatar object", "user_id", user.ID, "storage_key", key, "error", err)
				apierror.New("bad_gateway", http.StatusBadGateway, "failed to delete avatar").Write(w)
				return
			}
		}
	}

	if err := h.store.UpdateUserAvatar(r.Context(), user.ID, store.ManagedAvatar{}); err != nil {
		h.logger.Error("failed to clear avatar", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to delete avatar").Write(w)
		return
	}
	user.AvatarStorageKey = ""
	user.AvatarPreviewStorageKey = ""
	user.AvatarMasterStorageKey = ""
	user.AvatarURL = ""

	h.recordAudit(r, user.ID.String(), "user.avatar.delete", "user", user.ID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) buildProfileResponse(ctx context.Context, user *store.User) profileResponse {
	avatarURL, avatarPreviewURL := h.resolveAvatarURLs(ctx, user.AvatarStorageKey, user.AvatarPreviewStorageKey, user.AvatarURL)
	return profileResponse{
		ID:               user.ID.String(),
		Email:            user.Email,
		Phone:            user.Phone,
		DisplayName:      user.DisplayName,
		AvatarURL:        avatarURL,
		AvatarPreviewURL: avatarPreviewURL,
	}
}

func (h *Handler) createAvatarUploadIntent(ctx context.Context, userID, contentType string, contentLength int64, filename string) (*avatar.UploadIntentResponse, error) {
	contentType = normalizeAvatarContentType(contentType)
	if err := validateAvatarUploadRequest(contentType, contentLength); err != nil {
		return nil, err
	}
	return h.avatarClient.CreateUploadIntent(ctx, avatar.UploadIntentRequest{
		UserID:        userID,
		ContentType:   contentType,
		ContentLength: contentLength,
		Filename:      strings.TrimSpace(filename),
	})
}

func normalizeAvatarUploadSetRequest(req avatarUploadSetIntentRequest) (map[string]avatarUploadSetAssetRequest, error) {
	if len(req.Assets) != len(managedAvatarVariantKinds) {
		return nil, errors.New("assets must include preview, default, and master")
	}

	assets := make(map[string]avatarUploadSetAssetRequest, len(req.Assets))
	for _, asset := range req.Assets {
		kind := strings.TrimSpace(strings.ToLower(asset.Kind))
		if !isManagedAvatarVariantKind(kind) {
			return nil, errors.New("assets include an unsupported kind")
		}
		if _, exists := assets[kind]; exists {
			return nil, errors.New("assets include duplicate kinds")
		}
		contentType := normalizeAvatarContentType(asset.ContentType)
		if contentType != managedAvatarContentType {
			return nil, errors.New("managed avatar assets must use image/webp")
		}
		if err := validateAvatarUploadRequest(contentType, asset.ContentLength); err != nil {
			return nil, err
		}
		asset.Kind = kind
		asset.ContentType = contentType
		asset.Filename = strings.TrimSpace(asset.Filename)
		if asset.Filename == "" {
			asset.Filename = kind + ".webp"
		}
		assets[kind] = asset
	}

	for _, kind := range managedAvatarVariantKinds {
		if _, ok := assets[kind]; !ok {
			return nil, errors.New("assets must include preview, default, and master")
		}
	}
	return assets, nil
}

func validateAvatarUploadRequest(contentType string, contentLength int64) error {
	if _, ok := allowedAvatarContentTypes[contentType]; !ok {
		return errors.New("unsupported avatar content_type")
	}
	if contentLength <= 0 || contentLength > maxAvatarUploadBytes {
		return errors.New("content_length is out of bounds")
	}
	return nil
}

func validateFinalizedAvatar(finalized *avatar.FinalizeAvatarResponse, managed bool) error {
	if finalized == nil {
		return errors.New("avatar service returned no storage key")
	}
	if strings.TrimSpace(finalized.StorageKey) == "" {
		return errors.New("avatar service returned no storage key")
	}
	if finalized.ContentType == "" {
		return nil
	}
	contentType := normalizeAvatarContentType(finalized.ContentType)
	if managed {
		if contentType != managedAvatarContentType {
			return errors.New("avatar service returned unsupported content type")
		}
		return nil
	}
	if _, ok := allowedAvatarContentTypes[contentType]; !ok {
		return errors.New("avatar service returned unsupported content type")
	}
	return nil
}

func normalizeAvatarContentType(contentType string) string {
	return strings.TrimSpace(strings.ToLower(contentType))
}

func isManagedAvatarVariantKind(kind string) bool {
	for _, candidate := range managedAvatarVariantKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

func (h *Handler) issueAvatarUploadSetToken(userID string, intentIDs map[string]string) (string, error) {
	keys := h.sessionMgr.Keys()
	now := time.Now()
	return jwtx.Sign(keys, map[string]any{
		"sub":            userID,
		"aud":            avatarUploadSetAudience,
		"iat":            now.Unix(),
		"nbf":            now.Unix(),
		"exp":            now.Add(avatarUploadSetTTL).Unix(),
		"avatar_intents": intentIDs,
	})
}

func (h *Handler) verifyAvatarUploadSetToken(token, userID string) (map[string]string, error) {
	keys := h.sessionMgr.Keys()
	verified, err := jwtx.VerifyWithKey(token, keys.PublicKey, &jwtx.VerifyConfig{
		AllowedAlgorithms: []string{keys.Algorithm},
		RequiredAudience:  avatarUploadSetAudience,
	})
	if err != nil {
		return nil, err
	}

	sub, _ := verified.Claims["sub"].(string)
	if strings.TrimSpace(sub) == "" || sub != userID {
		return nil, errors.New("avatar upload token subject mismatch")
	}

	rawIntents, ok := verified.Claims["avatar_intents"].(map[string]any)
	if !ok {
		return nil, errors.New("avatar upload token missing intents")
	}

	out := make(map[string]string, len(managedAvatarVariantKinds))
	for _, kind := range managedAvatarVariantKinds {
		value, ok := rawIntents[kind].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, errors.New("avatar upload token missing intent")
		}
		out[kind] = strings.TrimSpace(value)
	}
	return out, nil
}

func managedAvatarKeysFromUser(user *store.User) []string {
	if user == nil {
		return nil
	}
	return managedAvatarKeys(store.ManagedAvatar{
		DefaultStorageKey: user.AvatarStorageKey,
		PreviewStorageKey: user.AvatarPreviewStorageKey,
		MasterStorageKey:  user.AvatarMasterStorageKey,
	})
}

func managedAvatarKeys(avatar store.ManagedAvatar) []string {
	return dedupeNonEmptyStrings([]string{
		strings.TrimSpace(avatar.DefaultStorageKey),
		strings.TrimSpace(avatar.PreviewStorageKey),
		strings.TrimSpace(avatar.MasterStorageKey),
	})
}

func keysToDelete(previous, keep []string) []string {
	keepSet := make(map[string]struct{}, len(keep))
	for _, key := range keep {
		keepSet[key] = struct{}{}
	}

	out := make([]string, 0, len(previous))
	for _, key := range dedupeNonEmptyStrings(previous) {
		if _, ok := keepSet[key]; ok {
			continue
		}
		out = append(out, key)
	}
	return out
}

func dedupeNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (h *Handler) deleteAvatarKeys(ctx context.Context, userID string, keys []string) {
	for _, key := range dedupeNonEmptyStrings(keys) {
		if err := h.avatarClient.DeleteObject(ctx, key); err != nil {
			h.logger.Warn("failed to delete avatar object", "user_id", userID, "storage_key", key, "error", err)
		}
	}
}

func (h *Handler) resolveAvatarURLs(ctx context.Context, avatarStorageKey, avatarPreviewStorageKey, legacyURL string) (string, string) {
	avatarURL := h.resolveAvatarURL(ctx, avatarStorageKey, legacyURL)
	if strings.TrimSpace(avatarPreviewStorageKey) == "" {
		return avatarURL, ""
	}
	if h.avatarClient == nil {
		return avatarURL, ""
	}
	url, err := h.avatarClient.SignedReadURL(ctx, avatarPreviewStorageKey)
	if err != nil {
		h.logger.Warn("failed to resolve avatar preview url", "storage_key", avatarPreviewStorageKey, "error", err)
		return avatarURL, ""
	}
	return avatarURL, url
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
