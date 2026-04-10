package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
)

const AttributionCookieName = "csar_attribution"

var ErrInvalidAttributionCookie = errors.New("invalid attribution cookie")

type attributionCookieState struct {
	Version        int               `json:"version"`
	SourceType     string            `json:"source_type"`
	SourceKey      string            `json:"source_key"`
	SourceMetadata map[string]string `json:"source_metadata,omitempty"`
	TouchedAt      time.Time         `json:"touched_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
}

func SetAttributionCookie(w http.ResponseWriter, touch *store.AttributionTouch, secure bool, sameSite http.SameSite) error {
	if touch == nil || touch.SourceType == "" || touch.SourceKey == "" || touch.TouchedAt.IsZero() || touch.ExpiresAt.IsZero() {
		return ErrInvalidAttributionCookie
	}
	if !touch.ExpiresAt.After(touch.TouchedAt) {
		return ErrInvalidAttributionCookie
	}

	payload, err := json.Marshal(attributionCookieState{
		Version:        1,
		SourceType:     touch.SourceType,
		SourceKey:      touch.SourceKey,
		SourceMetadata: store.CloneAttributionMetadata(touch.SourceMetadata),
		TouchedAt:      touch.TouchedAt.UTC(),
		ExpiresAt:      touch.ExpiresAt.UTC(),
	})
	if err != nil {
		return err
	}

	maxAge := int(time.Until(touch.ExpiresAt).Seconds())
	if maxAge < 1 {
		return ErrInvalidAttributionCookie
	}

	http.SetCookie(w, &http.Cookie{
		Name:     AttributionCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(payload),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
	return nil
}

func ClearAttributionCookie(w http.ResponseWriter, secure bool, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     AttributionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func ReadAttributionCookie(r *http.Request) (*store.AttributionTouch, error) {
	cookie, err := r.Cookie(AttributionCookieName)
	if err != nil {
		return nil, err
	}
	if cookie.Value == "" {
		return nil, ErrInvalidAttributionCookie
	}

	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, ErrInvalidAttributionCookie
	}

	var payload attributionCookieState
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, ErrInvalidAttributionCookie
	}
	if payload.Version != 1 || payload.SourceType == "" || payload.SourceKey == "" || payload.TouchedAt.IsZero() || payload.ExpiresAt.IsZero() {
		return nil, ErrInvalidAttributionCookie
	}
	if !payload.ExpiresAt.After(payload.TouchedAt) || !time.Now().Before(payload.ExpiresAt) {
		return nil, ErrInvalidAttributionCookie
	}

	return &store.AttributionTouch{
		SourceType:     payload.SourceType,
		SourceKey:      payload.SourceKey,
		SourceMetadata: store.CloneAttributionMetadata(payload.SourceMetadata),
		TouchedAt:      payload.TouchedAt.UTC(),
		ExpiresAt:      payload.ExpiresAt.UTC(),
	}, nil
}
