package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const (
	permSessionsImpersonate = "platform.sessions.impersonate"

	impersonationGrantTTL   = 60 * time.Second
	impersonationSessionTTL = time.Hour
	impersonationReasonMax  = 500
)

// adminAuth resolves the caller for /admin/* endpoints. Impersonated sessions
// are rejected so an admin acting as a user can never reach admin surfaces or
// chain further impersonations.
func (h *Handler) adminAuth(r *http.Request) (string, *apierror.Response) {
	sess, user, ok := h.resolveAuth(r)
	if !ok {
		return "", apierror.New("not_authenticated", http.StatusUnauthorized, "not authenticated")
	}
	if sess != nil && sess.ImpersonatorUserID != nil {
		return "", apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "impersonated sessions cannot access admin endpoints")
	}
	return user.ID.String(), nil
}

type impersonationGrantRequest struct {
	UserID      string `json:"user_id"`
	Reason      string `json:"reason"`
	RedirectURL string `json:"redirect_url"`
}

func (h *Handler) handleCreateImpersonationGrant(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}
	if apiErr := h.requireSessionsPermission(r, subject, permSessionsImpersonate); apiErr != nil {
		apiErr.Write(w)
		return
	}

	var body impersonationGrantRequest
	if err := httpx.ReadJSON(r, &body); err != nil {
		httpx.WriteError(w, err)
		return
	}

	targetID, err := uuid.Parse(strings.TrimSpace(body.UserID))
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid user_id").Write(w)
		return
	}

	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		apierror.New("bad_request", http.StatusBadRequest, "reason is required").Write(w)
		return
	}
	if len([]rune(reason)) > impersonationReasonMax {
		apierror.New("bad_request", http.StatusBadRequest, "reason is too long").Write(w)
		return
	}

	redirectURL := strings.TrimSpace(body.RedirectURL)
	if redirectURL == "" {
		redirectURL = h.oauthMgr.FrontendURL()
	}
	if redirectURL == "" || !h.oauthMgr.ValidateRedirectURL(redirectURL) {
		apierror.New("bad_request", http.StatusBadRequest, "redirect_url is invalid or not allowed").Write(w)
		return
	}

	target, err := h.store.GetUserByID(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "user not found").Write(w)
			return
		}
		h.logger.Error("failed to load impersonation target", "user_id", targetID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create impersonation grant").Write(w)
		return
	}
	target = h.followMerge(r, target)
	if target == nil {
		apierror.New("not_found", http.StatusNotFound, "user not found").Write(w)
		return
	}
	if target.ID.String() == subject {
		apierror.New("bad_request", http.StatusBadRequest, "cannot impersonate yourself").Write(w)
		return
	}

	roles, err := h.authzClient.client.ListSubjectRoles(r.Context(), &pb.ListSubjectRolesRequest{
		Subject:   target.ID.String(),
		ScopeType: "platform",
	})
	if err != nil {
		h.logger.Error("failed to list target platform roles", "user_id", target.ID, "error", err)
		apierror.New("authz_error", http.StatusBadGateway, "authorization check failed").Write(w)
		return
	}
	if len(roles.Roles) > 0 {
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "cannot impersonate a user with platform roles").Write(w)
		return
	}

	token, err := randomToken()
	if err != nil {
		h.logger.Error("failed to generate impersonation token", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create impersonation grant").Write(w)
		return
	}

	now := time.Now().UTC()
	adminID := uuid.MustParse(subject)
	grant := &store.ImpersonationGrant{
		ID:           uuid.New(),
		TokenHash:    hashValue(token),
		AdminUserID:  adminID,
		TargetUserID: target.ID,
		Reason:       reason,
		RedirectURL:  redirectURL,
		CreatedAt:    now,
		ExpiresAt:    now.Add(impersonationGrantTTL),
	}
	if err := h.store.CreateImpersonationGrant(r.Context(), grant); err != nil {
		h.logger.Error("failed to persist impersonation grant", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create impersonation grant").Write(w)
		return
	}

	exchangeURL, err := h.buildImpersonationExchangeURL(token)
	if err != nil {
		h.logger.Error("failed to build impersonation exchange URL", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create impersonation grant").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"grant_id":       grant.ID.String(),
		"target_user_id": target.ID.String(),
		"target_email":   target.Email,
		"reason":         reason,
		"expires_at":     grant.ExpiresAt.Unix(),
	})
	h.recordAudit(r, subject, "impersonation.grant", "user", target.ID.String(), afterJSON)

	h.logger.Info("impersonation grant created",
		"admin_user_id", subject, "target_user_id", target.ID, "grant_id", grant.ID)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"exchange_url":        exchangeURL,
		"expires_in_seconds":  expiresInSeconds(grant.ExpiresAt),
		"session_ttl_seconds": int(impersonationSessionTTL.Seconds()),
		"target": map[string]string{
			"user_id": target.ID.String(),
			"email":   target.Email,
		},
	})
}

func (h *Handler) handleImpersonationExchange(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		apierror.New("bad_request", http.StatusBadRequest, "token is required").Write(w)
		return
	}

	grant, err := h.store.ConsumeImpersonationGrant(r.Context(), hashValue(token))
	if err != nil {
		if errors.Is(err, store.ErrImpersonationGrantUnavailable) {
			apierror.New("gone", http.StatusGone, "impersonation link has expired or was already used").Write(w)
			return
		}
		h.logger.Error("failed to consume impersonation grant", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to complete impersonation").Write(w)
		return
	}

	target, err := h.store.GetUserByID(r.Context(), grant.TargetUserID)
	if err != nil {
		h.logger.Error("impersonation target vanished", "user_id", grant.TargetUserID, "error", err)
		apierror.New("not_found", http.StatusNotFound, "user not found").Write(w)
		return
	}
	target = h.followMerge(r, target)
	if target == nil {
		apierror.New("not_found", http.StatusNotFound, "user not found").Write(w)
		return
	}

	sess, err := h.sessMgr.CreateImpersonated(r.Context(),
		target.ID, grant.AdminUserID, grant.Reason,
		r.UserAgent(), requestIPAddress(r), impersonationSessionTTL)
	if err != nil {
		h.logger.Error("failed to create impersonated session",
			"grant_id", grant.ID, "target_user_id", target.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create session").Write(w)
		return
	}

	http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))

	afterJSON, _ := json.Marshal(map[string]any{
		"grant_id":           grant.ID.String(),
		"target_user_id":     target.ID.String(),
		"reason":             grant.Reason,
		"session_expires_at": sess.ExpiresAt.Unix(),
	})
	h.recordAudit(r, grant.AdminUserID.String(), "impersonation.start", "user", target.ID.String(), afterJSON)

	h.logger.Info("impersonation session created",
		"admin_user_id", grant.AdminUserID, "target_user_id", target.ID, "grant_id", grant.ID)

	http.Redirect(w, r, grant.RedirectURL, http.StatusSeeOther)
}

func (h *Handler) buildImpersonationExchangeURL(token string) (string, error) {
	base := strings.TrimSpace(h.oauthMgr.FrontendURL())
	if base == "" {
		return "", errors.New("frontend_url is empty")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref := &url.URL{Path: "/auth/impersonate/exchange"}
	if u.Path != "" && u.Path != "/" {
		ref.Path = strings.TrimRight(u.Path, "/") + ref.Path
	}
	exchange := u.ResolveReference(ref)
	exchange.RawQuery = url.Values{"token": []string{token}}.Encode()
	return exchange.String(), nil
}
