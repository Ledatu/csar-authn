package handler

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/store"
)

// sessionCookie builds an http.Cookie with the standard session attributes.
// value and maxAge vary per call site; everything else is from config.
func (h *Handler) sessionCookie(value string, maxAge int) *http.Cookie {
	cfg := h.cfg.Load()
	return &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    value,
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(cfg.Cookie.SameSite),
	}
}

// resolveAuth resolves the caller's identity from either:
//  1. Authorization: Bearer <jwt> header
//  2. Session cookie (opaque session ID)
//
// Returns (session, user, true) on success. session is nil for Bearer auth.
// Does NOT write to ResponseWriter — callers handle error responses.
func (h *Handler) resolveAuth(r *http.Request) (*store.Session, *store.User, bool) {
	cfg := h.cfg.Load()

	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		claims, err := h.sessionMgr.VerifyToken(strings.TrimPrefix(auth, "Bearer "))
		if err == nil {
			if userID, err := uuid.Parse(claims.Sub); err == nil {
				if user, err := h.store.GetUserByID(r.Context(), userID); err == nil {
					user = h.followMerge(r, user)
					if user != nil {
						identity := claims.Caller
						if identity != nil {
							copyIdentity := *identity
							copyIdentity.EffectiveSubject = user.ID.String()
							identity = &copyIdentity
						}
						setAuthenticatedContext(r, user, identity)
						return nil, user, true
					}
				}
			}
		}
	}

	// Try all cookies with the configured name. During migration from JWT
	// cookies to opaque session IDs, the browser may send both (different
	// Domain attributes make them distinct cookies with the same name).
	// r.Cookie() only returns the first match, so we iterate manually.
	for _, cookie := range r.Cookies() {
		if cookie.Name != cfg.Cookie.Name {
			continue
		}
		sess, err := h.sessMgr.Validate(r.Context(), cookie.Value)
		if err != nil {
			continue
		}
		user, err := h.store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			continue
		}
		user = h.followMerge(r, user)
		if user != nil {
			setAuthenticatedContext(r, user, sessionIdentity(sess, user))
			return sess, user, true
		}
	}
	return nil, nil, false
}

// Authn authenticates its own public ingress. Replace, rather than merge, any
// gateway assertions so client-provided caller/origin data cannot enter audit.
// Request IDs are correlation only; authentication comes from the session/JWT.
func setAuthenticatedContext(r *http.Request, user *store.User, identity *caller.Identity) {
	id, _ := gatewayctx.FromContext(r.Context())
	verified := gatewayctx.Identity{Subject: user.ID.String(), Caller: identity, RequestID: id.RequestID}
	*r = *r.WithContext(gatewayctx.NewContext(r.Context(), &verified))
}

// followMerge walks the merged_into chain until it reaches the canonical
// (unmerged) account. A hop limit guards against cycles or runaway chains.
func (h *Handler) followMerge(r *http.Request, user *store.User) *store.User {
	const maxHops = 5
	seen := make(map[uuid.UUID]struct{}, maxHops)
	cur := user
	for i := 0; i < maxHops; i++ {
		if cur.MergedInto == nil {
			return cur
		}
		if _, cycle := seen[cur.ID]; cycle {
			h.logger.Error("merged_into cycle detected", "user", cur.ID)
			return nil
		}
		seen[cur.ID] = struct{}{}
		next, err := h.store.GetUserByID(r.Context(), *cur.MergedInto)
		if err != nil {
			h.logger.Warn("merged_into target not found",
				"source", cur.ID, "target", *cur.MergedInto, "error", err,
			)
			return nil
		}
		cur = next
	}
	h.logger.Error("merged_into chain exceeded hop limit", "user", user.ID)
	return nil
}

// authenticateRequest validates the caller via Bearer JWT or session cookie.
// On success for cookie auth it refreshes the cookie's MaxAge in the response.
// Returns (session, user, true) for cookie auth or (nil, user, true) for Bearer.
// On failure it writes an HTTP error and returns (nil, nil, false).
func (h *Handler) authenticateRequest(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User, bool) {
	sess, user, ok := h.resolveAuth(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return nil, nil, false
	}
	if sess != nil {
		http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))
	}
	return sess, user, true
}
