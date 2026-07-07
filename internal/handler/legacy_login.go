package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

const legacyTelegramProvider = "telegram"

type legacyTelegramSessionRequest struct {
	Token string `json:"token"`
}

type legacyTelegramIdentity struct {
	ProviderUserID string
	Username       string
}

func (h *Handler) handleLegacyTelegramSession(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	legacyCfg := cfg.LegacyLogin.TelegramJWT
	if !legacyCfg.Enabled || legacyEndpointExpired(legacyCfg, time.Now()) {
		apierror.New("not_found", http.StatusNotFound, "legacy login is not available").Write(w)
		return
	}

	var body legacyTelegramSessionRequest
	if err := httpx.ReadJSON(r, &body); err != nil {
		httpx.WriteError(w, err)
		return
	}

	identity, err := verifyLegacyTelegramJWT(strings.TrimSpace(body.Token), legacyCfg, time.Now())
	if err != nil {
		h.logger.Warn("legacy telegram JWT rejected", "error", err)
		apierror.New("not_authenticated", http.StatusUnauthorized, "legacy token is invalid").Write(w)
		return
	}

	displayName := legacyTelegramDisplayName(identity.Username)
	acct := &store.OAuthAccount{
		Provider:       legacyTelegramProvider,
		ProviderUserID: identity.ProviderUserID,
		DisplayName:    displayName,
	}
	if identity.Username != "" {
		acct.ProviderMetadata = map[string]interface{}{"legacy_username": identity.Username}
	} else if existing, lookupErr := h.store.GetOAuthAccount(r.Context(), legacyTelegramProvider, identity.ProviderUserID); lookupErr == nil {
		acct.DisplayName = existing.DisplayName
		acct.ProviderMetadata = existing.ProviderMetadata
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		h.logger.Warn("failed to preload legacy telegram oauth account", "provider_user_id", identity.ProviderUserID, "error", lookupErr)
	}

	user, result, err := h.store.FindOrCreateUser(r.Context(), acct, "", "", displayName, "")
	if err != nil {
		h.logger.Error("failed to find or create legacy telegram account", "provider_user_id", identity.ProviderUserID, "error", err)
		apierror.New("not_authenticated", http.StatusUnauthorized, "legacy token is invalid").Write(w)
		return
	}
	user = h.followMerge(r, user)
	if user == nil {
		apierror.New("not_authenticated", http.StatusUnauthorized, "legacy token is invalid").Write(w)
		return
	}

	sess, err := h.sessMgr.Create(r.Context(), user.ID, r.UserAgent(), requestIPAddress(r))
	if err != nil {
		h.logger.Error("failed to create session from legacy telegram JWT", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create session").Write(w)
		return
	}

	http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))
	after := map[string]interface{}{
		"provider":         legacyTelegramProvider,
		"provider_user_id": identity.ProviderUserID,
		"created_new_user": result == store.ResultCreatedNewUser,
	}
	if identity.Username != "" {
		after["legacy_username"] = identity.Username
	}
	afterJSON, _ := json.Marshal(after)
	h.recordAudit(r, user.ID.String(), "legacy_login.telegram_session", "user", user.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func legacyEndpointExpired(cfg config.LegacyTelegramJWTConfig, now time.Time) bool {
	return !cfg.EndpointEnabledUntil.IsZero() && now.After(cfg.EndpointEnabledUntil)
}

func verifyLegacyTelegramJWT(tokenString string, cfg config.LegacyTelegramJWTConfig, now time.Time) (legacyTelegramIdentity, error) {
	if tokenString == "" {
		return legacyTelegramIdentity{}, errors.New("missing token")
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithJSONNumber(),
		jwt.WithLeeway(30 * time.Second),
	}
	if cfg.Issuer != "" {
		options = append(options, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		options = append(options, jwt.WithAudience(cfg.Audience))
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(options...)
	_, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
		}
		return []byte(cfg.HMACSecret), nil
	})
	if err != nil {
		return legacyTelegramIdentity{}, fmt.Errorf("verify token: %w", err)
	}

	iat, err := legacyNumericDate(claims, "iat")
	if err != nil {
		return legacyTelegramIdentity{}, err
	}
	if iat.After(now.Add(30 * time.Second)) {
		return legacyTelegramIdentity{}, errors.New("token issued in the future")
	}
	if cfg.MaxTokenAge.Duration > 0 {
		if now.After(iat.Add(cfg.MaxTokenAge.Duration)) {
			return legacyTelegramIdentity{}, errors.New("token exceeds max age")
		}
	}

	providerID, err := legacyTelegramID(claims["id"])
	if err != nil {
		return legacyTelegramIdentity{}, err
	}
	return legacyTelegramIdentity{
		ProviderUserID: providerID,
		Username:       legacyTelegramUsername(claims["username"]),
	}, nil
}

func legacyNumericDate(claims jwt.MapClaims, name string) (time.Time, error) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, fmt.Errorf("missing %s", name)
	}
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid %s", name)
		}
		return time.Unix(n, 0), nil
	case float64:
		return time.Unix(int64(v), 0), nil
	default:
		return time.Time{}, fmt.Errorf("invalid %s", name)
	}
}

func legacyTelegramID(value any) (string, error) {
	switch v := value.(type) {
	case json.Number:
		if _, err := v.Int64(); err != nil {
			return "", errors.New("invalid telegram id")
		}
		return v.String(), nil
	case float64:
		if v <= 0 || v != float64(int64(v)) {
			return "", errors.New("invalid telegram id")
		}
		return strconv.FormatInt(int64(v), 10), nil
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return "", errors.New("missing telegram id")
		}
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return "", errors.New("invalid telegram id")
		}
		return v, nil
	default:
		return "", errors.New("missing telegram id")
	}
}

func legacyTelegramUsername(value any) string {
	raw, ok := value.(string)
	if !ok {
		return ""
	}
	username := strings.TrimPrefix(strings.TrimSpace(raw), "@")
	if len(username) < 5 || len(username) > 32 {
		return ""
	}
	for _, r := range username {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' {
			continue
		}
		return ""
	}
	return username
}

func legacyTelegramDisplayName(username string) string {
	if username == "" {
		return ""
	}
	return "@" + username
}
