package oauth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/markbates/goth/gothic"

	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
)

// CallbackHandler returns an http.Handler that completes the OAuth flow.
// It handles two intents:
//   - "login" (default): lookup-or-create user, issue JWT
//   - "link": link the provider to an already-authenticated user
func CallbackHandler(
	st store.Store,
	sessionMgr *session.Manager,
	oauthMgr *Manager,
	cookieName string,
	cookieSecure bool,
	cookieSameSite http.SameSite,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the provider in the query so Goth can find it.
		provider := extractProvider(r)
		if provider == "" {
			http.Error(w, "missing provider", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		q.Set("provider", provider)
		r.URL.RawQuery = q.Encode()

		// Read intent before CompleteUserAuth — it clears the Goth session.
		intent, _ := gothic.GetFromSession("intent", r)

		// Complete the OAuth exchange.
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			logger.Error("oauth callback failed", "provider", provider, "error", err)
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		logger.Info("oauth callback received",
			"provider", gothUser.Provider,
			"provider_user_id", gothUser.UserID,
			"email", gothUser.Email,
		)

		// Determine email verification status.
		emailVerified := ExtractEmailVerified(gothUser, oauthMgr.IsTrusted(provider))

		// Build the OAuth account from the Goth user.
		acct := &store.OAuthAccount{
			Provider:       gothUser.Provider,
			ProviderUserID: gothUser.UserID,
			Email:          gothUser.Email,
			DisplayName:    gothUser.Name,
			AvatarURL:      gothUser.AvatarURL,
			AccessToken:    gothUser.AccessToken,
			RefreshToken:   gothUser.RefreshToken,
			EmailVerified:  emailVerified,
		}
		if !gothUser.ExpiresAt.IsZero() {
			t := gothUser.ExpiresAt
			acct.ExpiresAt = &t
		}

		// Extract phone number (Telegram provides this via OIDC phone scope).
		var phone string
		if pn, ok := gothUser.RawData["phone_number"]; ok {
			if s, ok := pn.(string); ok {
				phone = s
			}
		}

		if intent == "link" {
			handleLinkCallback(w, r, st, sessionMgr, oauthMgr, cookieName, acct, phone, provider, logger)
			return
		}

		// Default: login flow.
		handleLoginCallback(w, r, st, sessionMgr, oauthMgr, cookieName, cookieSecure, cookieSameSite, acct, gothUser.Email, phone, gothUser.Name, gothUser.AvatarURL, provider, logger)
	})
}

// handleLoginCallback handles the default login/register flow.
func handleLoginCallback(
	w http.ResponseWriter, r *http.Request,
	st store.Store,
	sessionMgr *session.Manager,
	oauthMgr *Manager,
	cookieName string,
	cookieSecure bool,
	cookieSameSite http.SameSite,
	acct *store.OAuthAccount,
	email, phone, displayName, avatarURL, provider string,
	logger *slog.Logger,
) {
	frontendURL := oauthMgr.FrontendURL()
	if frontendURL == "" {
		frontendURL = "/"
	}

	user, result, err := st.FindOrCreateUser(r.Context(), acct, email, phone, displayName, avatarURL)
	if err != nil {
		if errors.Is(err, store.ErrUnverifiedEmailConflict) {
			logger.Warn("unverified email conflicts with existing user",
				"provider", provider,
				"email", email,
			)
			redirectURL := httpx.AppendQuery(frontendURL, "error", "email_conflict", "provider", provider)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		logger.Error("find or create user failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch result {
	case store.ResultCreatedNewUser:
		logger.Info("new user created", "user_id", user.ID, "email", user.Email)
	case store.ResultLinkedToExisting:
		logger.Info("auto-linked provider to existing user", "user_id", user.ID, "provider", provider)
	default:
		logger.Info("existing user authenticated", "user_id", user.ID, "email", user.Email)
	}

	// Issue JWT.
	token, err := sessionMgr.IssueToken(user.ID.String(), user.Email, user.DisplayName)
	if err != nil {
		logger.Error("token issuance failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
		MaxAge:   int(sessionMgr.TTL().Seconds()),
	})

	http.Redirect(w, r, frontendURL, http.StatusTemporaryRedirect)
}

// handleLinkCallback handles the explicit account linking flow.
// The user must already be authenticated (have a valid session cookie).
func handleLinkCallback(
	w http.ResponseWriter, r *http.Request,
	st store.Store,
	sessionMgr *session.Manager,
	oauthMgr *Manager,
	cookieName string,
	acct *store.OAuthAccount,
	phone, provider string,
	logger *slog.Logger,
) {
	frontendURL := oauthMgr.FrontendURL()
	if frontendURL == "" {
		frontendURL = "/"
	}

	// Verify the user is authenticated.
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		logger.Warn("link callback without session cookie", "provider", provider)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "not_authenticated")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	claims, err := sessionMgr.VerifyToken(cookie.Value)
	if err != nil {
		logger.Warn("link callback with invalid session", "provider", provider, "error", err)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "invalid_session")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		logger.Error("invalid user id in session", "sub", claims.Sub)
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	// Link the provider account to the authenticated user.
	if err := st.LinkOAuthAccount(r.Context(), userID, acct); err != nil {
		if errors.Is(err, store.ErrProviderAlreadyLinked) {
			logger.Warn("provider account already linked to another user",
				"provider", provider,
				"provider_user_id", acct.ProviderUserID,
			)
			redirectURL := httpx.AppendQuery(frontendURL, "error", "already_linked", "provider", provider)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		logger.Error("link oauth account failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// If the provider supplied a phone and the user doesn't have one, store it.
	if phone != "" {
		user, err := st.GetUserByID(r.Context(), userID)
		if err == nil && user.Phone == "" {
			user.Phone = phone
			if err := st.UpdateUser(r.Context(), user); err != nil {
				logger.Warn("failed to update user phone on link", "user_id", userID, "error", err)
			}
		}
	}

	logger.Info("provider linked to user", "user_id", userID, "provider", provider)
	redirectURL := httpx.AppendQuery(frontendURL, "linked", provider)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
