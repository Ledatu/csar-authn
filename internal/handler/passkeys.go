package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/passkey"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
)

type passkeyResponse struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	CreatedAt      int64    `json:"created_at"`
	LastUsedAt     *int64   `json:"last_used_at,omitempty"`
	Attachment     string   `json:"attachment,omitempty"`
	Transports     []string `json:"transports,omitempty"`
	BackupEligible bool     `json:"backup_eligible"`
	BackupState    bool     `json:"backup_state"`
}

type passkeyFinishRegistrationRequest struct {
	Label      string          `json:"label"`
	Credential json.RawMessage `json:"credential"`
}

type passkeyVerifyRequest struct {
	Credential json.RawMessage `json:"credential"`
}

func passkeyToResponse(passkey *store.Passkey) passkeyResponse {
	resp := passkeyResponse{
		ID:             passkey.ID.String(),
		Label:          passkey.Label,
		CreatedAt:      passkey.CreatedAt.Unix(),
		Attachment:     passkey.Attachment,
		Transports:     passkey.Transports,
		BackupEligible: passkey.BackupEligible,
		BackupState:    passkey.BackupState,
	}
	if passkey.LastUsedAt != nil {
		ts := passkey.LastUsedAt.Unix()
		resp.LastUsedAt = &ts
	}
	return resp
}

func (h *Handler) handleMePasskeys(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	passkeys, err := h.store.ListPasskeysByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to list passkeys", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list passkeys").Write(w)
		return
	}
	resp := make([]passkeyResponse, 0, len(passkeys))
	for i := range passkeys {
		resp = append(resp, passkeyToResponse(&passkeys[i]))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"passkeys": resp})
}

func (h *Handler) handleBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	passkeys, err := h.store.ListPasskeysByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to list passkeys for registration", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey registration").Write(w)
		return
	}
	options, challenge, err := h.passkeySvc.BeginRegistration(user, passkeys)
	if err != nil {
		h.logger.Error("failed to begin passkey registration", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey registration").Write(w)
		return
	}
	if err := h.store.CreatePasskeyChallenge(r.Context(), challenge); err != nil {
		h.logger.Error("failed to store passkey registration challenge", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey registration").Write(w)
		return
	}
	if err := h.setPasskeyStateCookie(w, passkey.ChallengeKindRegistration, challenge.ID); err != nil {
		h.logger.Error("failed to sign passkey registration state", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey registration").Write(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (h *Handler) handleFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	var body passkeyFinishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Credential) == 0 {
		apierror.New("bad_request", http.StatusBadRequest, "credential is required").Write(w)
		return
	}
	challengeID, err := h.readPasskeyStateCookie(r, passkey.ChallengeKindRegistration)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "passkey state is missing or invalid").Write(w)
		return
	}
	challenge, err := h.store.ConsumePasskeyChallenge(r.Context(), challengeID, passkey.ChallengeKindRegistration)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "passkey registration challenge expired or already used").Write(w)
		return
	}
	h.clearPasskeyStateCookie(w)
	if challenge.UserID == nil || *challenge.UserID != user.ID {
		apierror.New("bad_request", http.StatusBadRequest, "passkey registration challenge does not match the authenticated user").Write(w)
		return
	}
	existing, err := h.store.ListPasskeysByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to load existing passkeys", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to complete passkey registration").Write(w)
		return
	}
	label := strings.TrimSpace(body.Label)
	if label == "" {
		label = defaultPasskeyLabel(time.Now().UTC())
	}
	created, err := h.passkeySvc.FinishRegistration(user, existing, challenge, body.Credential, label)
	if err != nil {
		h.logger.Warn("passkey registration verification failed", "user_id", user.ID, "error", err)
		apierror.New("bad_request", http.StatusBadRequest, "invalid passkey registration response").Write(w)
		return
	}
	if err := h.store.CreatePasskey(r.Context(), created); err != nil {
		if errors.Is(err, store.ErrPasskeyAlreadyLinked) {
			apierror.New("conflict", http.StatusConflict, "passkey is already linked to an account").Write(w)
			return
		}
		h.logger.Error("failed to persist passkey", "user_id", user.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to save passkey").Write(w)
		return
	}
	afterJSON, _ := json.Marshal(map[string]any{
		"label": created.Label,
	})
	h.recordAudit(r, user.ID.String(), "passkey.register", "passkey", created.ID.String(), afterJSON)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(passkeyToResponse(created))
}

func (h *Handler) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}
	passkeyID, err := uuid.Parse(strings.TrimSpace(r.PathValue("passkey_id")))
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid passkey_id").Write(w)
		return
	}
	if err := h.store.DeletePasskey(r.Context(), passkeyID, user.ID); err != nil {
		if errors.Is(err, store.ErrLastLoginMethod) {
			apierror.New("bad_request", http.StatusBadRequest, "cannot remove the last login method").Write(w)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "passkey not found").Write(w)
			return
		}
		h.logger.Error("failed to delete passkey", "user_id", user.ID, "passkey_id", passkeyID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to delete passkey").Write(w)
		return
	}
	h.recordAudit(r, user.ID.String(), "passkey.delete", "passkey", passkeyID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	options, challenge, err := h.passkeySvc.BeginLogin()
	if err != nil {
		h.logger.Error("failed to begin passkey login", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey login").Write(w)
		return
	}
	if err := h.store.CreatePasskeyChallenge(r.Context(), challenge); err != nil {
		h.logger.Error("failed to store passkey login challenge", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey login").Write(w)
		return
	}
	if err := h.setPasskeyStateCookie(w, passkey.ChallengeKindLogin, challenge.ID); err != nil {
		h.logger.Error("failed to sign passkey login state", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to prepare passkey login").Write(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (h *Handler) handleFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var body passkeyVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Credential) == 0 {
		apierror.New("bad_request", http.StatusBadRequest, "credential is required").Write(w)
		return
	}
	challengeID, err := h.readPasskeyStateCookie(r, passkey.ChallengeKindLogin)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "passkey state is missing or invalid").Write(w)
		return
	}
	challenge, err := h.store.ConsumePasskeyChallenge(r.Context(), challengeID, passkey.ChallengeKindLogin)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "passkey login challenge expired or already used").Write(w)
		return
	}
	h.clearPasskeyStateCookie(w)
	result, err := h.passkeySvc.FinishLogin(challenge, body.Credential, func(credentialID, userHandle []byte) (*store.User, *store.Passkey, error) {
		passkeyRecord, err := h.store.GetPasskeyByCredentialID(r.Context(), credentialID)
		if err != nil {
			return nil, nil, err
		}
		user, err := h.store.GetUserByID(r.Context(), passkeyRecord.UserID)
		if err != nil {
			return nil, nil, err
		}
		user = h.followMerge(r, user)
		if user == nil {
			return nil, nil, store.ErrNotFound
		}
		return user, passkeyRecord, nil
	})
	if err != nil {
		h.logger.Warn("passkey login verification failed", "error", err)
		apierror.New("bad_request", http.StatusBadRequest, "invalid passkey login response").Write(w)
		return
	}
	now := time.Now().UTC()
	if err := h.store.UpdatePasskeyUsage(r.Context(), result.Passkey.ID, result.SignCount, result.BackupState, result.UserVerified, now); err != nil {
		h.logger.Warn("failed to update passkey usage", "passkey_id", result.Passkey.ID, "error", err)
	}
	sess, err := h.sessMgr.Create(r.Context(), result.User.ID, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		h.logger.Error("session creation failed after passkey login", "user_id", result.User.ID, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create session").Write(w)
		return
	}
	http.SetCookie(w, h.sessionCookie(sess.ID, h.sessMgr.CookieMaxAge(sess)))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setPasskeyStateCookie(w http.ResponseWriter, kind string, challengeID uuid.UUID) error {
	value, err := h.passkeySvc.EncodeState(challengeID, kind)
	if err != nil {
		return err
	}
	cfg := h.cfg.Load()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Passkeys.StateCookieName,
		Value:    value,
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		MaxAge:   int(cfg.Passkeys.ChallengeTTL.Std().Seconds()),
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(cfg.Cookie.SameSite),
	})
	return nil
}

func (h *Handler) readPasskeyStateCookie(r *http.Request, expectedKind string) (uuid.UUID, error) {
	cfg := h.cfg.Load()
	cookie, err := r.Cookie(cfg.Passkeys.StateCookieName)
	if err != nil {
		return uuid.Nil, err
	}
	return h.passkeySvc.DecodeState(cookie.Value, expectedKind)
}

func (h *Handler) clearPasskeyStateCookie(w http.ResponseWriter) {
	cfg := h.cfg.Load()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Passkeys.StateCookieName,
		Value:    "",
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(cfg.Cookie.SameSite),
	})
}

func defaultPasskeyLabel(now time.Time) string {
	return "Passkey " + now.Format("2006-01-02")
}
