package emailotp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
)

const (
	providerEmail = store.EmailProvider
	otpLength     = 6
)

// Handler holds dependencies for email OTP endpoints.
type Handler struct {
	store   store.Store
	sessMgr *session.SessionManager
	sender  Sender
	cfg     *config.Config
	logger  *slog.Logger
}

// NewHandler creates an email OTP handler with all dependencies.
func NewHandler(st store.Store, sessMgr *session.SessionManager, sender Sender, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		store:   st,
		sessMgr: sessMgr,
		sender:  sender,
		cfg:     cfg,
		logger:  logger.With("component", "emailotp"),
	}
}

// HandleStart initiates an email OTP flow.
// POST /auth/email-otp/start
func (h *Handler) HandleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, err)
		return
	}
	email, err := store.NormalizeEmailString(req.Email)
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cfg := h.cfg.EmailOTP
	ip := requestIPAddress(r)

	if ok := h.checkStartLimits(w, r, email, ip, cfg); !ok {
		return
	}

	intent := "login"
	var userID *uuid.UUID
	if cookie, err := r.Cookie(h.cfg.Cookie.Name); err == nil {
		if sess, err := h.sessMgr.Validate(ctx, cookie.Value); err == nil {
			intent = "link"
			userID = &sess.UserID
		}
	}

	code, err := generateCode()
	if err != nil {
		h.logger.Error("generating email OTP code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	challenge := &store.EmailOTPChallenge{
		ID:        uuid.New(),
		Email:     email,
		CodeHash:  hashCode(code),
		Intent:    intent,
		UserID:    userID,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: now.Add(cfg.CodeTTL.Duration),
		UserAgent: r.UserAgent(),
		IPAddress: ip,
	}
	if err := h.store.CreateEmailOTPChallenge(ctx, challenge); err != nil {
		h.logger.Error("creating email OTP challenge", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.sender.SendOTP(ctx, email, code); err != nil {
		h.logger.Error("sending email OTP", "error", err)
		http.Error(w, "could not send code", http.StatusBadGateway)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"challenge_id":       challenge.ID.String(),
		"intent":             intent,
		"expires_in_seconds": int(time.Until(challenge.ExpiresAt).Seconds()),
	})
}

func (h *Handler) checkStartLimits(w http.ResponseWriter, r *http.Request, email string, ip string, cfg *config.EmailOTPConfig) bool {
	ctx := r.Context()
	count, err := h.store.CountPendingEmailOTPChallengesByIP(ctx, ip)
	if err != nil {
		h.logger.Error("counting email OTP challenges by IP", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if count >= cfg.MaxPendingPerIP {
		http.Error(w, "too many pending challenges", http.StatusTooManyRequests)
		return false
	}

	count, err = h.store.CountPendingEmailOTPChallengesByEmail(ctx, email)
	if err != nil {
		h.logger.Error("counting email OTP challenges by email", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if count >= cfg.MaxPendingPerEmail {
		http.Error(w, "too many pending challenges", http.StatusTooManyRequests)
		return false
	}

	latest, err := h.store.GetLatestEmailOTPChallengeByEmail(ctx, email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.logger.Error("getting latest email OTP challenge", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if latest != nil && time.Since(latest.CreatedAt) < cfg.Cooldown.Duration {
		http.Error(w, "code requested too recently", http.StatusTooManyRequests)
		return false
	}
	return true
}

// HandleVerify verifies an email OTP and performs login or link side effects.
// POST /auth/email-otp/verify
func (h *Handler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, err)
		return
	}
	id, err := uuid.Parse(req.ChallengeID)
	if err != nil {
		http.Error(w, "invalid challenge id", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}

	challenge, err := h.store.VerifyEmailOTPChallenge(r.Context(), id, hashCode(req.Code), h.cfg.EmailOTP.MaxAttempts)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrEmailOTPInvalidCode):
			http.Error(w, "invalid code", http.StatusUnauthorized)
		case errors.Is(err, store.ErrEmailOTPTooManyAttempts):
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
		case errors.Is(err, store.ErrEmailOTPUnavailable):
			http.Error(w, "challenge expired or already used", http.StatusConflict)
		default:
			h.logger.Error("verifying email OTP challenge", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	acct := &store.OAuthAccount{
		Provider:       providerEmail,
		ProviderUserID: challenge.Email,
		Email:          challenge.Email,
		DisplayName:    challenge.Email,
		EmailVerified:  true,
	}

	switch challenge.Intent {
	case "login":
		h.finalizeLogin(w, r, challenge, acct)
	case "link":
		h.finalizeLink(w, r, challenge, acct)
	default:
		h.logger.Error("unknown email OTP intent", "intent", challenge.Intent)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) finalizeLogin(w http.ResponseWriter, r *http.Request, challenge *store.EmailOTPChallenge, acct *store.OAuthAccount) {
	ctx := r.Context()
	user, result, err := h.store.FindOrCreateUser(ctx, acct, challenge.Email, "", challenge.Email, "")
	if err != nil {
		h.logger.Error("find or create user by email OTP", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	switch result {
	case store.ResultCreatedNewUser:
		h.logger.Info("new user created via email OTP", "user_id", user.ID)
	case store.ResultLinkedToExisting:
		h.logger.Info("auto-linked via email OTP", "user_id", user.ID)
	default:
		h.logger.Info("existing user authenticated via email OTP", "user_id", user.ID)
	}

	sess, err := h.sessMgr.Create(ctx, user.ID, r.UserAgent(), requestIPAddress(r))
	if err != nil {
		h.logger.Error("session creation failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":  "authenticated",
		"user_id": user.ID.String(),
	})
}

func (h *Handler) finalizeLink(w http.ResponseWriter, r *http.Request, challenge *store.EmailOTPChallenge, acct *store.OAuthAccount) {
	ctx := r.Context()
	cookie, err := r.Cookie(h.cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	sess, err := h.sessMgr.Validate(ctx, cookie.Value)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	if challenge.UserID == nil || *challenge.UserID != sess.UserID {
		http.Error(w, "session user does not match challenge", http.StatusForbidden)
		return
	}
	if err := h.store.LinkOAuthAccount(ctx, sess.UserID, acct); err != nil {
		if errors.Is(err, store.ErrProviderAlreadyLinked) {
			h.handleMerge(w, r, challenge, sess.UserID)
			return
		}
		h.logger.Error("linking email OTP account", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":   "linked",
		"provider": providerEmail,
	})
}

func (h *Handler) handleMerge(w http.ResponseWriter, r *http.Request, challenge *store.EmailOTPChallenge, targetID uuid.UUID) {
	existingAcct, err := h.store.GetOAuthAccount(r.Context(), providerEmail, challenge.Email)
	if err != nil {
		h.logger.Error("looking up existing email account for merge", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sourceID := existingAcct.UserID
	if sourceID == targetID {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"result":   "linked",
			"provider": providerEmail,
		})
		return
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		h.logger.Error("generating merge token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokenStr := hex.EncodeToString(rawToken)
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  tokenHash,
		SourceUser: sourceID,
		TargetUser: targetID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	if err := h.store.CreateMergeRecord(r.Context(), rec); err != nil {
		h.logger.Error("creating email OTP merge record", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csar_merge",
		Value:    tokenStr,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(h.cfg.Cookie.SameSite),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":      "merge_available",
		"source_user": sourceID.String(),
		"merge_ready": true,
	})
}

func (h *Handler) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     h.cfg.Cookie.Name,
		Value:    value,
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(h.cfg.Cookie.SameSite),
	}
}

func generateCode() (string, error) {
	result := make([]byte, otpLength)
	max := big.NewInt(10)
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = byte('0' + n.Int64())
	}
	return string(result), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(h[:])
}

func requestIPAddress(r *http.Request) string {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
	}
	return ip
}
