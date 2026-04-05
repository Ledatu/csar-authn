package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

const (
	loginHandoffStatusPending  = "pending"
	loginHandoffStatusApproved = "approved"
	loginHandoffStatusDenied   = "denied"
	loginHandoffStatusExpired  = "expired"
	loginHandoffStatusConsumed = "consumed"

	qrLoginStateCookieName = "csar_qr_login_state"
)

type qrLoginStartRequest struct {
	RedirectURL string `json:"redirect_url"`
}

type qrLoginTokenRequest struct {
	Token string `json:"token"`
}

func (h *Handler) handleQRLoginStart(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	var body qrLoginStartRequest
	if err := httpx.ReadJSON(r, &body); err != nil {
		httpx.WriteError(w, err)
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
	ipAddress := requestIPAddress(r)
	count, err := h.store.CountPendingLoginHandoffs(r.Context(), ipAddress)
	if err != nil {
		h.logger.Error("failed to count pending QR login handoffs", "ip_address", ipAddress, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to start QR login").Write(w)
		return
	}
	if count >= cfg.QRLogin.MaxPendingPerIP {
		apierror.New("too_many_requests", http.StatusTooManyRequests, "too many pending QR login requests for this IP").Write(w)
		return
	}

	scanToken, err := randomToken()
	if err != nil {
		h.logger.Error("failed to generate QR login scan token", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to start QR login").Write(w)
		return
	}
	desktopSecret, err := randomToken()
	if err != nil {
		h.logger.Error("failed to generate QR login desktop secret", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to start QR login").Write(w)
		return
	}
	qrURL, err := h.buildQRLoginURL(scanToken)
	if err != nil {
		h.logger.Error("failed to build QR login URL", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to start QR login").Write(w)
		return
	}

	now := time.Now().UTC()
	handoff := &store.LoginHandoff{
		ID:                uuid.New(),
		ScanTokenHash:     hashValue(scanToken),
		DesktopSecretHash: hashValue(desktopSecret),
		RedirectURL:       redirectURL,
		Status:            loginHandoffStatusPending,
		DesktopUserAgent:  r.UserAgent(),
		DesktopIPAddress:  ipAddress,
		CreatedAt:         now,
		ExpiresAt:         now.Add(cfg.QRLogin.TTL.Duration),
	}
	if err := h.store.CreateLoginHandoff(r.Context(), handoff); err != nil {
		h.logger.Error("failed to persist QR login handoff", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to start QR login").Write(w)
		return
	}

	http.SetCookie(w, h.qrLoginStateCookie(desktopSecret, int(time.Until(handoff.ExpiresAt).Seconds())))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"request_id":         handoff.ID.String(),
		"qr_url":             qrURL,
		"expires_in_seconds": expiresInSeconds(handoff.ExpiresAt),
	})
}

func (h *Handler) handleQRLoginStatus(w http.ResponseWriter, r *http.Request) {
	handoff, ok := h.desktopLoginHandoff(w, r)
	if !ok {
		return
	}

	status := h.effectiveLoginHandoffStatus(r.Context(), handoff)
	if status == loginHandoffStatusDenied || status == loginHandoffStatusExpired || status == loginHandoffStatusConsumed {
		http.SetCookie(w, h.qrLoginStateCookie("", -1))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (h *Handler) handleQRLoginComplete(w http.ResponseWriter, r *http.Request) {
	handoff, ok := h.desktopLoginHandoff(w, r)
	if !ok {
		return
	}

	status := h.effectiveLoginHandoffStatus(r.Context(), handoff)
	if status != loginHandoffStatusApproved {
		if status == loginHandoffStatusDenied || status == loginHandoffStatusExpired || status == loginHandoffStatusConsumed {
			http.SetCookie(w, h.qrLoginStateCookie("", -1))
		}
		apierror.New("conflict", http.StatusConflict, "login handoff is not approved").Write(w)
		return
	}
	if handoff.ApprovedByUserID == nil {
		h.logger.Error("approved QR login handoff missing approver", "request_id", handoff.ID)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to complete QR login").Write(w)
		return
	}

	handoff, err := h.store.ConsumeApprovedLoginHandoff(r.Context(), handoff.ID)
	if err != nil {
		if errors.Is(err, store.ErrLoginHandoffUnavailable) {
			apierror.New("conflict", http.StatusConflict, "login handoff is no longer available").Write(w)
			return
		}
		h.logger.Error("failed to consume QR login handoff", "request_id", handoff.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to complete QR login").Write(w)
		return
	}

	sess, err := h.sessMgr.Create(r.Context(), *handoff.ApprovedByUserID, r.UserAgent(), requestIPAddress(r))
	if err != nil {
		h.logger.Error("failed to create session for QR login", "request_id", handoff.ID, "user_id", *handoff.ApprovedByUserID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create session").Write(w)
		return
	}

	http.SetCookie(w, h.qrLoginStateCookie("", -1))
	http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))

	afterJSON, _ := json.Marshal(map[string]any{
		"status":       handoff.Status,
		"redirect_url": handoff.RedirectURL,
	})
	h.recordAudit(r, handoff.ApprovedByUserID.String(), "qr_login.complete", "login_handoff", handoff.ID.String(), afterJSON)

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"redirect_url": handoff.RedirectURL})
}

func (h *Handler) handleQRLoginByToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	if token == "" {
		apierror.New("bad_request", http.StatusBadRequest, "token is required").Write(w)
		return
	}

	handoff, err := h.store.GetLoginHandoffByScanToken(r.Context(), hashValue(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "login handoff not found").Write(w)
			return
		}
		h.logger.Error("failed to load QR login handoff by token", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to load QR login handoff").Write(w)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":             h.effectiveLoginHandoffStatus(r.Context(), handoff),
		"expires_in_seconds": expiresInSeconds(handoff.ExpiresAt),
		"desktop": map[string]string{
			"user_agent": handoff.DesktopUserAgent,
			"ip_address": maskIPAddress(handoff.DesktopIPAddress),
		},
	})
}

func (h *Handler) handleQRLoginApprove(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	handoff, ok := h.loginHandoffFromTokenBody(w, r)
	if !ok {
		return
	}

	status := h.effectiveLoginHandoffStatus(r.Context(), handoff)
	if status != loginHandoffStatusPending {
		apierror.New("conflict", http.StatusConflict, "login handoff is not pending").Write(w)
		return
	}

	handoff, err := h.store.ApproveLoginHandoff(r.Context(), handoff.ID, user.ID)
	if err != nil {
		if errors.Is(err, store.ErrLoginHandoffUnavailable) {
			apierror.New("conflict", http.StatusConflict, "login handoff is no longer available").Write(w)
			return
		}
		h.logger.Error("failed to approve QR login handoff", "request_id", handoff.ID, "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to approve QR login").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"status":              handoff.Status,
		"approved_by_user_id": user.ID.String(),
	})
	h.recordAudit(r, user.ID.String(), "qr_login.approve", "login_handoff", handoff.ID.String(), afterJSON)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleQRLoginDeny(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	handoff, ok := h.loginHandoffFromTokenBody(w, r)
	if !ok {
		return
	}

	status := h.effectiveLoginHandoffStatus(r.Context(), handoff)
	if status != loginHandoffStatusPending {
		apierror.New("conflict", http.StatusConflict, "login handoff is not pending").Write(w)
		return
	}

	handoff, err := h.store.DenyLoginHandoff(r.Context(), handoff.ID)
	if err != nil {
		if errors.Is(err, store.ErrLoginHandoffUnavailable) {
			apierror.New("conflict", http.StatusConflict, "login handoff is no longer available").Write(w)
			return
		}
		h.logger.Error("failed to deny QR login handoff", "request_id", handoff.ID, "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to deny QR login").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"status": handoff.Status,
	})
	h.recordAudit(r, user.ID.String(), "qr_login.deny", "login_handoff", handoff.ID.String(), afterJSON)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) loginHandoffFromTokenBody(w http.ResponseWriter, r *http.Request) (*store.LoginHandoff, bool) {
	var body qrLoginTokenRequest
	if err := httpx.ReadJSON(r, &body); err != nil {
		httpx.WriteError(w, err)
		return nil, false
	}
	if strings.TrimSpace(body.Token) == "" {
		apierror.New("bad_request", http.StatusBadRequest, "token is required").Write(w)
		return nil, false
	}
	body.Token = strings.TrimSpace(body.Token)

	handoff, err := h.store.GetLoginHandoffByScanToken(r.Context(), hashValue(body.Token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "login handoff not found").Write(w)
			return nil, false
		}
		h.logger.Error("failed to load QR login handoff by token", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to load QR login handoff").Write(w)
		return nil, false
	}
	return handoff, true
}

func (h *Handler) desktopLoginHandoff(w http.ResponseWriter, r *http.Request) (*store.LoginHandoff, bool) {
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request id").Write(w)
		return nil, false
	}
	secretCookie, err := r.Cookie(qrLoginStateCookieName)
	if err != nil || strings.TrimSpace(secretCookie.Value) == "" {
		apierror.New("not_authenticated", http.StatusUnauthorized, "desktop login state is missing").Write(w)
		return nil, false
	}

	handoff, err := h.store.GetLoginHandoffStatusForDesktop(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "login handoff not found").Write(w)
			return nil, false
		}
		h.logger.Error("failed to load QR login handoff for desktop", "request_id", id, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to load QR login handoff").Write(w)
		return nil, false
	}
	if !hashedValueMatches(secretCookie.Value, handoff.DesktopSecretHash) {
		apierror.New("access_denied", http.StatusForbidden, "desktop login state does not match request").Write(w)
		return nil, false
	}
	return handoff, true
}

func (h *Handler) effectiveLoginHandoffStatus(ctx context.Context, handoff *store.LoginHandoff) string {
	now := time.Now()
	switch handoff.Status {
	case loginHandoffStatusPending:
		if !now.Before(handoff.ExpiresAt) {
			if err := h.store.ExpireLoginHandoff(ctx, handoff.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				h.logger.Warn("failed to expire QR login handoff", "request_id", handoff.ID, "error", err)
			}
			return loginHandoffStatusExpired
		}
	case loginHandoffStatusApproved:
		if !now.Before(handoff.ExpiresAt) {
			return loginHandoffStatusExpired
		}
	}
	return handoff.Status
}

func (h *Handler) qrLoginStateCookie(value string, maxAge int) *http.Cookie {
	cfg := h.cfg.Load()
	return &http.Cookie{
		Name:     qrLoginStateCookieName,
		Value:    value,
		Path:     "/auth/qr-login/",
		Domain:   cfg.Cookie.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(cfg.Cookie.SameSite),
	}
}

func (h *Handler) buildQRLoginURL(scanToken string) (string, error) {
	base := strings.TrimSpace(h.oauthMgr.FrontendURL())
	if base == "" {
		return "", fmt.Errorf("frontend_url is empty")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse frontend_url: %w", err)
	}
	ref := &url.URL{Path: "/login/qr"}
	if u.Path != "" && u.Path != "/" {
		ref.Path = strings.TrimRight(u.Path, "/") + "/login/qr"
	}
	qrURL := u.ResolveReference(ref)
	qrURL.RawQuery = url.Values{"token": []string{scanToken}}.Encode()
	return qrURL.String(), nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashValue(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hashedValueMatches(raw, hashed string) bool {
	rawHash := hashValue(raw)
	return subtle.ConstantTimeCompare([]byte(rawHash), []byte(hashed)) == 1
}

func requestIPAddress(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return normalizeIPAddress(parts[0])
		}
	}
	return normalizeIPAddress(r.RemoteAddr)
}

func normalizeIPAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return value
}

func maskIPAddress(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.x", v4[0], v4[1], v4[2])
	}

	parts := strings.Split(ip.String(), ":")
	if len(parts) > 4 {
		parts = parts[:4]
	}
	return strings.Join(parts, ":") + ":*"
}

func expiresInSeconds(expiresAt time.Time) int {
	remaining := int(time.Until(expiresAt).Seconds())
	if remaining < 0 {
		return 0
	}
	return remaining
}
