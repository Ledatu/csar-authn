package oauth

import (
	"log/slog"
	"net/http"

	"github.com/markbates/goth/gothic"

	"github.com/Ledatu/csar-auth/internal/session"
	"github.com/Ledatu/csar-auth/internal/store"
)

// CallbackHandler returns an http.Handler that completes the OAuth flow,
// performs lookup-or-create, and issues a session JWT.
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

		// Build the OAuth account from the Goth user.
		acct := &store.OAuthAccount{
			Provider:       gothUser.Provider,
			ProviderUserID: gothUser.UserID,
			Email:          gothUser.Email,
			DisplayName:    gothUser.Name,
			AvatarURL:      gothUser.AvatarURL,
			AccessToken:    gothUser.AccessToken,
			RefreshToken:   gothUser.RefreshToken,
		}
		if !gothUser.ExpiresAt.IsZero() {
			t := gothUser.ExpiresAt
			acct.ExpiresAt = &t
		}

		// Lookup-or-create the user.
		user, created, err := st.FindOrCreateUser(r.Context(), acct, gothUser.Email, gothUser.Name, gothUser.AvatarURL)
		if err != nil {
			logger.Error("find or create user failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if created {
			logger.Info("new user created", "user_id", user.ID, "email", user.Email)
		} else {
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

		// Redirect to frontend.
		frontendURL := oauthMgr.FrontendURL()
		if frontendURL == "" {
			frontendURL = "/"
		}
		http.Redirect(w, r, frontendURL, http.StatusTemporaryRedirect)
	})
}
