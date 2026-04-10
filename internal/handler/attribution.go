package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

const (
	defaultAttributionTouchTTL   = 30 * 24 * time.Hour
	maxAttributionBodyBytes      = 16 << 10
	maxAttributionMetadataItems  = 16
	maxAttributionFieldLength    = 128
	maxAttributionValueLength    = 512
	maxAttributionCookieLifetime = 365 * 24 * time.Hour
)

type captureAttributionRequest struct {
	SourceType     string            `json:"source_type"`
	SourceKey      string            `json:"source_key"`
	SourceMetadata map[string]string `json:"source_metadata"`
	TouchedAt      *time.Time        `json:"touched_at,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
}

type attributionResolveRequest struct {
	UserID  string `json:"user_id,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type attributionConsumeRequest struct {
	UserID  string `json:"user_id,omitempty"`
	Subject string `json:"subject,omitempty"`
	TouchID string `json:"touch_id"`
}

type attributionTouchResponse struct {
	ID             string            `json:"id,omitempty"`
	Subject        string            `json:"subject,omitempty"`
	SourceType     string            `json:"source_type,omitempty"`
	SourceKey      string            `json:"source_key,omitempty"`
	SourceMetadata map[string]string `json:"source_metadata,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	TouchedAt      time.Time         `json:"touched_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	ConsumedAt     *time.Time        `json:"consumed_at,omitempty"`
	Persisted      bool              `json:"persisted,omitempty"`
}

type attributionStateResponse struct {
	ActiveTouch          *attributionTouchResponse `json:"active_touch,omitempty"`
	PendingQualification bool                      `json:"pending_qualification"`
	Source               string                    `json:"source,omitempty"`
}

type attributionResolveResponse struct {
	Touch   *attributionTouchResponse  `json:"touch,omitempty"`
	Touches []attributionTouchResponse `json:"touches,omitempty"`
}

func (h *Handler) handleCaptureAttribution(w http.ResponseWriter, r *http.Request) {
	req, apiErr := decodeCaptureAttributionRequest(w, r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	touch, apiErr := buildCapturedAttributionTouch(req)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	source := "cookie"
	if _, user, ok := h.resolveAuth(r); ok {
		touch.UserID = user.ID
		stored, err := h.store.UpsertUserAttributionTouch(r.Context(), touch)
		if err != nil {
			h.logger.Error("failed to persist attribution touch", "user_id", user.ID, "error", err)
			apierror.New("internal_error", http.StatusInternalServerError, "failed to capture attribution touch").Write(w)
			return
		}
		touch = stored
		source = "user"
	}

	secure, sameSite := h.attributionCookieConfig()
	if err := oauth.SetAttributionCookie(w, touch, secure, sameSite); err != nil {
		h.logger.Error("failed to encode attribution cookie", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to capture attribution touch").Write(w)
		return
	}

	setAttributionBrowserHeaders(w)
	httpx.WriteJSON(w, http.StatusOK, attributionStateResponse{
		ActiveTouch:          attributionTouchToResponse(touch),
		PendingQualification: source == "user",
		Source:               source,
	})
}

func (h *Handler) handleCurrentAttribution(w http.ResponseWriter, r *http.Request) {
	touch, source, err := h.resolveCurrentAttribution(r)
	if err != nil {
		secure, sameSite := h.attributionCookieConfig()
		if errors.Is(err, oauth.ErrInvalidAttributionCookie) {
			oauth.ClearAttributionCookie(w, secure, sameSite)
		} else {
			h.logger.Error("failed to resolve current attribution", "error", err)
			apierror.New("internal_error", http.StatusInternalServerError, "failed to load attribution state").Write(w)
			return
		}
	}

	setAttributionBrowserHeaders(w)
	httpx.WriteJSON(w, http.StatusOK, attributionStateResponse{
		ActiveTouch:          attributionTouchToResponse(touch),
		PendingQualification: source == "user" && touch != nil,
		Source:               source,
	})
}

func (h *Handler) handleResolveServiceAttribution(w http.ResponseWriter, r *http.Request) {
	req, apiErr := decodeAttributionResolveRequest(w, r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	userID, apiErr := parseAttributionSubject(req.Subject, req.UserID)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	touch, err := h.store.GetActiveUserAttributionTouch(r.Context(), userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.logger.Error("failed to resolve service attribution", "subject", userID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to resolve attribution touch").Write(w)
		return
	}

	resp := attributionResolveResponse{Touches: []attributionTouchResponse{}}
	if err == nil && touch != nil {
		item := attributionTouchToResponse(touch)
		item.Subject = userID.String()
		resp.Touch = item
		resp.Touches = append(resp.Touches, *item)
	}

	setAttributionServiceHeaders(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleConsumeServiceAttribution(w http.ResponseWriter, r *http.Request) {
	req, apiErr := decodeAttributionConsumeRequest(w, r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	userID, apiErr := parseAttributionSubject(req.Subject, req.UserID)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}
	touchID, err := uuid.Parse(strings.TrimSpace(req.TouchID))
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "touch_id must be a valid UUID").Write(w)
		return
	}

	touch, err := h.store.ConsumeUserAttributionTouch(r.Context(), userID, touchID)
	if err != nil {
		if errors.Is(err, store.ErrAttributionUnavailable) {
			apierror.New("conflict", http.StatusConflict, "attribution touch is unavailable").Write(w)
			return
		}
		h.logger.Error("failed to consume service attribution", "subject", userID, "touch_id", touchID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to consume attribution touch").Write(w)
		return
	}

	item := attributionTouchToResponse(touch)
	item.Subject = userID.String()
	setAttributionServiceHeaders(w)
	httpx.WriteJSON(w, http.StatusOK, attributionResolveResponse{
		Touch:   item,
		Touches: []attributionTouchResponse{*item},
	})
}

func (h *Handler) resolveCurrentAttribution(r *http.Request) (*store.AttributionTouch, string, error) {
	if _, user, ok := h.resolveAuth(r); ok {
		touch, err := h.store.GetActiveUserAttributionTouch(r.Context(), user.ID)
		switch {
		case err == nil:
			return touch, "user", nil
		case errors.Is(err, store.ErrNotFound):
		default:
			return nil, "", err
		}
	}

	touch, err := oauth.ReadAttributionCookie(r)
	switch {
	case err == nil:
		return touch, "cookie", nil
	case errors.Is(err, http.ErrNoCookie):
		return nil, "", nil
	default:
		return nil, "", err
	}
}

func attributionTouchToResponse(touch *store.AttributionTouch) *attributionTouchResponse {
	if touch == nil {
		return nil
	}

	resp := &attributionTouchResponse{
		SourceType:     touch.SourceType,
		SourceKey:      touch.SourceKey,
		SourceMetadata: store.CloneAttributionMetadata(touch.SourceMetadata),
		Metadata:       store.CloneAttributionMetadata(touch.SourceMetadata),
		TouchedAt:      touch.TouchedAt,
		ExpiresAt:      touch.ExpiresAt,
		ConsumedAt:     touch.ConsumedAt,
		Persisted:      touch.UserID != uuid.Nil,
	}
	if touch.ID != uuid.Nil {
		resp.ID = touch.ID.String()
	}
	return resp
}

func decodeCaptureAttributionRequest(w http.ResponseWriter, r *http.Request) (*captureAttributionRequest, *apierror.Response) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAttributionBodyBytes)
	defer func() { _ = r.Body.Close() }()

	var req captureAttributionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid request body")
	}
	if dec.More() {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid request body")
	}
	return &req, nil
}

func decodeAttributionResolveRequest(w http.ResponseWriter, r *http.Request) (*attributionResolveRequest, *apierror.Response) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAttributionBodyBytes)
	defer func() { _ = r.Body.Close() }()

	var req attributionResolveRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid request body")
	}
	return &req, nil
}

func decodeAttributionConsumeRequest(w http.ResponseWriter, r *http.Request) (*attributionConsumeRequest, *apierror.Response) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAttributionBodyBytes)
	defer func() { _ = r.Body.Close() }()

	var req attributionConsumeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid request body")
	}
	return &req, nil
}

func parseAttributionSubject(subject, userID string) (uuid.UUID, *apierror.Response) {
	raw := strings.TrimSpace(subject)
	if raw == "" {
		raw = strings.TrimSpace(userID)
	}
	if raw == "" {
		return uuid.Nil, apierror.New("bad_request", http.StatusBadRequest, "subject is required")
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, apierror.New("bad_request", http.StatusBadRequest, "subject must be a valid user ID")
	}
	return id, nil
}

func buildCapturedAttributionTouch(req *captureAttributionRequest) (*store.AttributionTouch, *apierror.Response) {
	if req == nil {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "missing request body")
	}

	sourceType := strings.TrimSpace(req.SourceType)
	sourceKey := strings.TrimSpace(req.SourceKey)
	if sourceType == "" || sourceKey == "" {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "source_type and source_key are required")
	}
	if len(sourceType) > maxAttributionFieldLength || len(sourceKey) > maxAttributionValueLength {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "source_type or source_key is too long")
	}

	metadata, apiErr := sanitizeAttributionMetadata(req.SourceMetadata)
	if apiErr != nil {
		return nil, apiErr
	}

	touchedAt := time.Now().UTC()
	if req.TouchedAt != nil && !req.TouchedAt.IsZero() {
		touchedAt = req.TouchedAt.UTC()
	}
	expiresAt := touchedAt.Add(defaultAttributionTouchTTL)
	if req.ExpiresAt != nil && !req.ExpiresAt.IsZero() {
		expiresAt = req.ExpiresAt.UTC()
	}
	if !expiresAt.After(touchedAt) {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "expires_at must be after touched_at")
	}
	if expiresAt.Sub(touchedAt) > maxAttributionCookieLifetime {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "attribution lifetime is too long")
	}

	return &store.AttributionTouch{
		ID:             uuid.New(),
		SourceType:     sourceType,
		SourceKey:      sourceKey,
		SourceMetadata: metadata,
		TouchedAt:      touchedAt,
		ExpiresAt:      expiresAt,
	}, nil
}

func sanitizeAttributionMetadata(raw map[string]string) (map[string]string, *apierror.Response) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxAttributionMetadataItems {
		return nil, apierror.New("bad_request", http.StatusBadRequest, "too many source_metadata items")
	}

	out := make(map[string]string, len(raw))
	for key, value := range raw {
		cleanKey := strings.TrimSpace(key)
		if cleanKey == "" || len(cleanKey) > maxAttributionFieldLength {
			return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid source_metadata key")
		}
		if len(value) > maxAttributionValueLength {
			return nil, apierror.New("bad_request", http.StatusBadRequest, "invalid source_metadata value")
		}
		out[cleanKey] = value
	}
	return out, nil
}

func (h *Handler) attributionCookieConfig() (bool, http.SameSite) {
	if h.oauthMgr != nil {
		return h.oauthMgr.CookieConfig()
	}
	cfg := h.Config()
	return cfg.Cookie.Secure, httpx.ParseSameSite(cfg.Cookie.SameSite)
}

func setAttributionBrowserHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization, Cookie")
}

func setAttributionServiceHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization")
}
