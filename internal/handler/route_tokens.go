package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/jwtx"

	"github.com/ledatu/csar-authn/internal/store"
)

func (h *Handler) resolveValidatedSession(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	cfg := h.cfg.Load()
	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "missing session", http.StatusUnauthorized)
		return nil, nil, false
	}

	sess, err := h.sessMgr.Validate(r.Context(), cookie.Value)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return nil, nil, false
	}

	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return nil, nil, false
	}
	user = h.followMerge(r, user)
	if user == nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return nil, nil, false
	}

	return sess, user, true
}

func (h *Handler) handleValidateWithTokens(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := h.resolveValidatedSession(w, r)
	if !ok {
		return
	}

	var req authntokens.ValidateRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, err)
		return
	}

	resp := authntokens.ValidateResponse{
		Headers: map[string]string{
			"X-User-ID":              user.ID.String(),
			"X-User-Email":           user.Email,
			gatewayctx.HeaderSubject: user.ID.String(),
		},
	}
	if sess.ImpersonatorUserID != nil {
		resp.Headers["X-Impersonator-ID"] = sess.ImpersonatorUserID.String()
	}
	if len(req.IssueTokens) == 0 {
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}

	accounts, err := h.store.GetOAuthAccountsByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to load oauth accounts for route tokens", "user_id", user.ID, "error", err)
		http.Error(w, "failed to resolve route token claims", http.StatusInternalServerError)
		return
	}
	accountsByProvider := oauthAccountsByProvider(accounts)
	cfg := h.cfg.Load()

	for _, tokenReq := range req.IssueTokens {
		profileName := strings.TrimSpace(tokenReq.Profile)
		if profileName == "" {
			continue
		}
		profile, found := cfg.RouteTokens[profileName]
		if !found || !profile.Enabled {
			resp.Errors = append(resp.Errors, authntokens.IssueTokenError{
				Profile: profileName,
				Reason:  authntokens.ReasonUnknownProfile,
			})
			h.logger.Warn("route token profile unavailable", "profile", profileName, "found", found)
			continue
		}

		claims, issueErr := h.buildRouteTokenClaims(profile, sess, user, accountsByProvider)
		if issueErr != "" {
			resp.Errors = append(resp.Errors, authntokens.IssueTokenError{
				Profile: profileName,
				Reason:  issueErr,
			})
			h.logger.Warn("route token claim resolution failed", "profile", profileName, "reason", issueErr, "user_id", user.ID)
			continue
		}

		expiresAt := time.Now().Add(profile.TTL.Duration)
		token, err := jwtx.SignHMACWithConfig([]byte(profile.Secret.Plaintext()), profile.Algorithm, &jwtx.SigningConfig{
			Issuer:   profile.Issuer,
			Audience: profile.Audience,
			TTL:      profile.TTL.Duration,
		}, claims)
		if err != nil {
			resp.Errors = append(resp.Errors, authntokens.IssueTokenError{
				Profile: profileName,
				Reason:  authntokens.ReasonSigningFailed,
			})
			h.logger.Error("route token signing failed", "profile", profileName, "user_id", user.ID, "error", err)
			continue
		}

		resp.Tokens = append(resp.Tokens, authntokens.IssuedToken{
			Profile:   profileName,
			Token:     token,
			ExpiresAt: expiresAt,
		})
		h.logger.Debug("route token issued", "profile", profileName, "user_id", user.ID)
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) buildRouteTokenClaims(profile authnconfig.RouteTokenConfig, sess *store.Session, user *store.User, accounts map[string]store.OAuthAccount) (jwt.MapClaims, string) {
	claims := jwt.MapClaims{}
	for k, v := range profile.StaticClaims {
		claims[k] = v
	}
	for claimName, source := range profile.Claims {
		value, ok := resolveRouteTokenValue(source.Source, sess, user, accounts)
		required := profile.OnMissingClaim == authnconfig.RouteTokenMissingFailClosed
		if source.Required != nil {
			required = *source.Required
		}
		if !ok || value == "" {
			if required {
				return nil, authntokens.ReasonMissingClaim
			}
			continue
		}

		coerced, err := coerceRouteTokenClaim(value, source.As)
		if err != nil {
			if required {
				return nil, authntokens.ReasonMissingClaim
			}
			continue
		}
		claims[claimName] = coerced
	}
	return claims, ""
}

func oauthAccountsByProvider(accounts []store.OAuthAccount) map[string]store.OAuthAccount {
	out := make(map[string]store.OAuthAccount, len(accounts))
	for _, acct := range accounts {
		if _, exists := out[acct.Provider]; !exists {
			out[acct.Provider] = acct
		}
	}
	return out
}

func resolveRouteTokenValue(source string, sess *store.Session, user *store.User, accounts map[string]store.OAuthAccount) (string, bool) {
	parts := strings.Split(source, ".")
	switch {
	case len(parts) == 2 && parts[0] == "user":
		switch parts[1] {
		case "id":
			return user.ID.String(), true
		case "email":
			return user.Email, user.Email != ""
		case "phone":
			return user.Phone, user.Phone != ""
		case "display_name":
			return user.DisplayName, user.DisplayName != ""
		}
	case len(parts) == 2 && parts[0] == "session" && parts[1] == "id":
		return sess.ID, sess.ID != ""
	case len(parts) >= 3 && parts[0] == "oauth":
		acct, ok := accounts[parts[1]]
		if !ok {
			return "", false
		}
		switch parts[2] {
		case "provider_user_id":
			return acct.ProviderUserID, acct.ProviderUserID != ""
		case "email":
			return acct.Email, acct.Email != ""
		case "metadata":
			if len(parts) != 4 || acct.ProviderMetadata == nil {
				return "", false
			}
			v, ok := acct.ProviderMetadata[parts[3]]
			if !ok || v == nil {
				return "", false
			}
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

func coerceRouteTokenClaim(value, as string) (any, error) {
	switch as {
	case "", authnconfig.RouteTokenClaimString:
		return value, nil
	case authnconfig.RouteTokenClaimInt:
		return strconv.ParseInt(value, 10, 64)
	case authnconfig.RouteTokenClaimBool:
		return strconv.ParseBool(value)
	default:
		return nil, fmt.Errorf("unsupported claim coercion %q", as)
	}
}
