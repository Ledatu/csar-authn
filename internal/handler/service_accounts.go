package handler

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/audit"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const permServiceAccountsManage = "platform.service_accounts.manage"

func (h *Handler) requireSAPermission(r *http.Request, subject string) *apierror.Response {
	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		ScopeType: "platform",
		Resource:  "admin",
		Action:    permServiceAccountsManage,
	})
	if err != nil {
		h.logger.Error("authz check failed", "subject", subject, "error", err)
		return apierror.New("authz_error", http.StatusBadGateway, "authorization check failed")
	}
	if !resp.Allowed {
		return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "insufficient permissions")
	}
	return nil
}

func (h *Handler) recordAudit(r *http.Request, actor, action, targetType, targetID string, afterState json.RawMessage) {
	if h.auditRecorder == nil {
		return
	}
	event := &audit.Event{
		Actor:      actor,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		ScopeType:  "platform",
		AfterState: afterState,
	}
	if err := h.auditRecorder.Record(r.Context(), event); err != nil {
		h.logger.Warn("failed to record audit event", "action", action, "error", err)
	}
}

// --- Response types ---

type saResponse struct {
	Name              string   `json:"name"`
	AllowedAudiences  []string `json:"allowed_audiences"`
	AllowAllAudiences bool     `json:"allow_all_audiences"`
	TokenTTL          string   `json:"token_ttl"`
	Status            string   `json:"status"`
	CreatedAt         int64    `json:"created_at"`
	RotatedAt         *int64   `json:"rotated_at,omitempty"`
	RevokedAt         *int64   `json:"revoked_at,omitempty"`
	ReactivatedAt     *int64   `json:"reactivated_at,omitempty"`
	Revision          int64    `json:"revision"`
	Generation        int64    `json:"generation"`
	Source            string   `json:"source"`
	ShadowedDBStatus  string   `json:"shadowed_database_status,omitempty"`
	Reactivated       bool     `json:"reactivated,omitempty"`
}

type saDetailResponse struct {
	saResponse
	PublicKeyPEM string `json:"public_key_pem"`
}

func saToResponse(sa *store.ServiceAccount) saResponse {
	resp := saResponse{
		Name:              sa.Name,
		AllowedAudiences:  append([]string{}, sa.AllowedAudiences...),
		AllowAllAudiences: sa.AllowAllAudiences,
		TokenTTL:          sa.TokenTTL.String(),
		Status:            sa.Status,
		CreatedAt:         sa.CreatedAt.Unix(),
		Revision:          sa.Revision,
		Generation:        sa.Generation,
		Source:            "database",
	}
	if sa.RotatedAt != nil {
		ts := sa.RotatedAt.Unix()
		resp.RotatedAt = &ts
	}
	if sa.RevokedAt != nil {
		ts := sa.RevokedAt.Unix()
		resp.RevokedAt = &ts
	}
	if sa.ReactivatedAt != nil {
		ts := sa.ReactivatedAt.Unix()
		resp.ReactivatedAt = &ts
	}
	return resp
}

func (h *Handler) bootstrapSA(name string) *saDetailResponse {
	for _, account := range h.Config().STS.Accounts {
		if account.Name != name {
			continue
		}
		return &saDetailResponse{
			saResponse: saResponse{
				Name:              account.Name,
				AllowedAudiences:  append([]string{}, account.AllowedAudiences...),
				AllowAllAudiences: account.AllowAllAudiences,
				TokenTTL:          account.TokenTTL.Std().String(),
				Status:            "active",
				Source:            "config",
			},
			PublicKeyPEM: account.PublicKeyPEM,
		}
	}
	return nil
}

func validateSAPolicy(audiences []string, ttlText string) ([]string, time.Duration, error) {
	if len(audiences) == 0 || len(audiences) > 32 {
		return nil, 0, errors.New("allowed_audiences must contain 1 to 32 entries")
	}
	unique := make(map[string]struct{}, len(audiences))
	for _, item := range audiences {
		audience := strings.TrimSpace(item)
		if audience == "" || len(audience) > 128 {
			return nil, 0, errors.New("audience must contain 1 to 128 characters")
		}
		unique[audience] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for audience := range unique {
		result = append(result, audience)
	}
	sort.Strings(result)
	if ttlText == "" {
		ttlText = "1h"
	}
	ttl, err := time.ParseDuration(ttlText)
	if err != nil || ttl < time.Second || ttl > 24*time.Hour || ttl%time.Second != 0 {
		return nil, 0, errors.New("token_ttl must be a whole-second duration from 1s to 24h")
	}
	return result, ttl, nil
}

// --- Handlers ---

func (h *Handler) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "revoked" && status != "all" {
		apierror.New("bad_request", http.StatusBadRequest, "status must be active, revoked, or all").Write(w)
		return
	}
	accounts, err := h.store.ListServiceAccounts(r.Context(), status)
	if err != nil {
		h.logger.Error("failed to list service accounts", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to list service accounts").Write(w)
		return
	}

	byName := make(map[string]saResponse, len(accounts))
	for _, sa := range accounts {
		byName[sa.Name] = saToResponse(&sa)
	}
	if status != "revoked" {
		for _, bootstrap := range h.Config().STS.Accounts {
			item := h.bootstrapSA(bootstrap.Name).saResponse
			if shadowed, ok := byName[item.Name]; ok {
				item.ShadowedDBStatus = shadowed.Status
			}
			byName[item.Name] = item
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	resp := make([]saResponse, 0, len(names))
	for _, name := range names {
		resp = append(resp, byName[name])
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type createSARequest struct {
	Name              string   `json:"name"`
	PublicKeyPEM      string   `json:"public_key_pem"`
	AllowedAudiences  []string `json:"allowed_audiences"`
	AllowAllAudiences bool     `json:"allow_all_audiences"`
	TokenTTL          string   `json:"token_ttl"`
}

func (h *Handler) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	var body createSARequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "request body must contain name").Write(w)
		return
	}
	if body.PublicKeyPEM == "" {
		apierror.New("bad_request", http.StatusBadRequest, "public_key_pem is required").Write(w)
		return
	}
	if err := validatePEM(body.PublicKeyPEM); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid public key PEM: "+err.Error()).Write(w)
		return
	}

	audiences, ttl, err := validateSAPolicy(body.AllowedAudiences, body.TokenTTL)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	}
	if h.bootstrapSA(body.Name) != nil {
		apierror.New("config_managed", http.StatusConflict, "service account is managed by configuration").Write(w)
		return
	}
	previous, err := h.store.GetServiceAccount(r.Context(), body.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.logger.Error("failed to inspect service account before create", "name", body.Name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to inspect service account").Write(w)
		return
	}

	sa := &store.ServiceAccount{
		Name:              body.Name,
		PublicKeyPEM:      body.PublicKeyPEM,
		AllowedAudiences:  audiences,
		AllowAllAudiences: body.AllowAllAudiences,
		TokenTTL:          ttl,
		Status:            "active",
	}

	reactivated, err := h.store.CreateOrReactivateServiceAccount(r.Context(), sa)
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			apierror.New("active_name_exists", http.StatusConflict, "active service account already exists").Write(w)
			return
		}
		if errors.Is(err, store.ErrKeyUnchanged) {
			apierror.New("key_unchanged", http.StatusConflict, "reactivation requires a new public key").Write(w)
			return
		}
		h.logger.Error("failed to create service account", "name", body.Name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to create service account").Write(w)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"name":                sa.Name,
		"allowed_audiences":   sa.AllowedAudiences,
		"allow_all_audiences": sa.AllowAllAudiences,
		"token_ttl":           sa.TokenTTL.String(),
		"revision":            sa.Revision,
		"generation":          sa.Generation,
	})
	action := "service_account.create"
	if reactivated {
		action = "service_account.reactivate"
		if previous != nil {
			afterJSON, _ = json.Marshal(map[string]any{
				"before": map[string]any{
					"status":              previous.Status,
					"allowed_audiences":   previous.AllowedAudiences,
					"allow_all_audiences": previous.AllowAllAudiences,
					"token_ttl":           previous.TokenTTL.String(),
					"revision":            previous.Revision,
					"generation":          previous.Generation,
				},
				"after": map[string]any{
					"status":              sa.Status,
					"allowed_audiences":   sa.AllowedAudiences,
					"allow_all_audiences": sa.AllowAllAudiences,
					"token_ttl":           sa.TokenTTL.String(),
					"revision":            sa.Revision,
					"generation":          sa.Generation,
				},
			})
		}
	}
	h.recordAudit(r, subject, action, "service_account", sa.Name, afterJSON)

	resp := saToResponse(sa)
	resp.Reactivated = reactivated
	w.Header().Set("Content-Type", "application/json")
	if reactivated {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleGetServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}
	if bootstrap := h.bootstrapSA(name); bootstrap != nil {
		if shadowed, err := h.store.GetServiceAccount(r.Context(), name); err == nil {
			bootstrap.ShadowedDBStatus = shadowed.Status
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bootstrap)
		return
	}

	sa, err := h.store.GetServiceAccount(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found").Write(w)
			return
		}
		h.logger.Error("failed to get service account", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to get service account").Write(w)
		return
	}

	resp := saDetailResponse{
		saResponse:   saToResponse(sa),
		PublicKeyPEM: sa.PublicKeyPEM,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type updateSAPolicyRequest struct {
	AllowedAudiences  []string `json:"allowed_audiences"`
	AllowAllAudiences bool     `json:"allow_all_audiences"`
	TokenTTL          string   `json:"token_ttl"`
}

func (h *Handler) handleUpdateServiceAccountPolicy(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}
	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}
	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}
	if h.bootstrapSA(name) != nil {
		apierror.New("config_managed", http.StatusConflict, "service account is managed by configuration").Write(w)
		return
	}
	revisionText := strings.Trim(r.Header.Get("If-Match"), `"`)
	if revisionText == "" {
		apierror.New("precondition_required", http.StatusPreconditionRequired, "If-Match revision is required").Write(w)
		return
	}
	revision, err := strconv.ParseInt(revisionText, 10, 64)
	if err != nil || revision <= 0 {
		apierror.New("bad_request", http.StatusBadRequest, "invalid If-Match revision").Write(w)
		return
	}
	var body updateSAPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TokenTTL == "" {
		apierror.New("bad_request", http.StatusBadRequest, "policy must contain audiences and token_ttl").Write(w)
		return
	}
	audiences, ttl, err := validateSAPolicy(body.AllowedAudiences, body.TokenTTL)
	if err != nil {
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	}
	previous, err := h.store.GetServiceAccount(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		apierror.New("not_found", http.StatusNotFound, "service account not found").Write(w)
		return
	}
	if err != nil {
		h.logger.Error("failed to read service account", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to read service account").Write(w)
		return
	}
	if previous.Status != "active" {
		apierror.New("revoked", http.StatusConflict, "reactivate the service account before editing its policy").Write(w)
		return
	}
	if previous.Revision != revision {
		apierror.New("stale_revision", http.StatusPreconditionFailed, "service account changed; reload and retry").Write(w)
		return
	}
	previousAudiences := append([]string(nil), previous.AllowedAudiences...)
	sort.Strings(previousAudiences)
	if slices.Equal(previousAudiences, audiences) && previous.AllowAllAudiences == body.AllowAllAudiences && previous.TokenTTL == ttl {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(saToResponse(previous))
		return
	}
	updated, err := h.store.UpdateServiceAccountPolicy(r.Context(), name, audiences, body.AllowAllAudiences, ttl, revision)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			apierror.New("not_found", http.StatusNotFound, "service account not found").Write(w)
		case errors.Is(err, store.ErrInactive):
			apierror.New("revoked", http.StatusConflict, "service account is revoked").Write(w)
		case errors.Is(err, store.ErrRevisionMismatch):
			apierror.New("stale_revision", http.StatusPreconditionFailed, "service account changed; reload and retry").Write(w)
		default:
			h.logger.Error("failed to update service account policy", "name", name, "error", err)
			apierror.New("internal_error", http.StatusInternalServerError, "failed to update service account policy").Write(w)
		}
		return
	}
	afterJSON, _ := json.Marshal(map[string]any{
		"before": map[string]any{
			"allowed_audiences":   previous.AllowedAudiences,
			"allow_all_audiences": previous.AllowAllAudiences,
			"token_ttl":           previous.TokenTTL.String(),
			"revision":            previous.Revision,
		},
		"after": map[string]any{
			"allowed_audiences":   updated.AllowedAudiences,
			"allow_all_audiences": updated.AllowAllAudiences,
			"token_ttl":           updated.TokenTTL.String(),
			"revision":            updated.Revision,
		},
	})
	h.recordAudit(r, subject, "service_account.policy_update", "service_account", name, afterJSON)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(saToResponse(updated))
}

func (h *Handler) handleRevokeServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}
	if h.bootstrapSA(name) != nil {
		apierror.New("config_managed", http.StatusConflict, "service account is managed by configuration").Write(w)
		return
	}

	if err := h.store.RevokeServiceAccount(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found or already revoked").Write(w)
			return
		}
		h.logger.Error("failed to revoke service account", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to revoke service account").Write(w)
		return
	}

	h.recordAudit(r, subject, "service_account.revoke", "service_account", name, nil)

	w.WriteHeader(http.StatusNoContent)
}

type rotateSARequest struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

func (h *Handler) handleRotateServiceAccount(w http.ResponseWriter, r *http.Request) {
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
		return
	}

	if apiErr := h.requireSAPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		apierror.New("bad_request", http.StatusBadRequest, "service account name is required").Write(w)
		return
	}
	if h.bootstrapSA(name) != nil {
		apierror.New("config_managed", http.StatusConflict, "service account is managed by configuration").Write(w)
		return
	}

	var body rotateSARequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublicKeyPEM == "" {
		apierror.New("bad_request", http.StatusBadRequest, "public_key_pem is required").Write(w)
		return
	}

	if err := validatePEM(body.PublicKeyPEM); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid public key PEM: "+err.Error()).Write(w)
		return
	}

	if err := h.store.UpdateServiceAccountKey(r.Context(), name, body.PublicKeyPEM); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apierror.New("not_found", http.StatusNotFound, "service account not found or not active").Write(w)
			return
		}
		h.logger.Error("failed to rotate service account key", "name", name, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to rotate key").Write(w)
		return
	}

	h.recordAudit(r, subject, "service_account.rotate", "service_account", name, nil)

	w.WriteHeader(http.StatusNoContent)
}

func validatePEM(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return errors.New("no PEM block found")
	}
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	return err
}
