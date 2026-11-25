package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	csarerrors "github.com/ledatu/csar-core/errors"
	"github.com/ledatu/csar-core/httpx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const maxActiveAPIKeys = 5
const apiKeyLifetime = 90 * 24 * time.Hour
const apiKeyPrefix = "aurum_pat_"

// Legacy introspectors require the exact v1 length and must reject scoped v2
// keys instead of assuming their historical, hardcoded adverts:read authority.
const apiKeyScopedPrefix = "aurum_pat_v2_"

func (h *Handler) apiKeyStore() store.APICredentialStore {
	keys, _ := h.store.(store.APICredentialStore)
	return keys
}

func (h *Handler) sellerCredentialOwner(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	// Seller-issued credentials require the owner’s direct browser session.
	if r.Header.Get("Authorization") != "" {
		httpx.WriteError(w, csarerrors.Unauthorized("session required"))
		return nil, false
	}
	sess, user, ok := h.authenticateRequest(w, r)
	if !ok || sess == nil {
		if ok {
			httpx.WriteError(w, csarerrors.Unauthorized("session required"))
		}
		return nil, false
	}
	if sess.ImpersonatorUserID != nil {
		httpx.WriteError(w, csarerrors.Forbidden("seller credentials require the owner session"))
		return nil, false
	}
	return user, true
}

func apiKeyMutationOriginAllowed(origin string) bool {
	switch origin {
	case "https://seller.aurum-sky.net", "https://dev-seller.aurum-sky.net:3005":
		return true
	default:
		return false
	}
}

func (h *Handler) checkAPIKeyMutationOrigin(w http.ResponseWriter, r *http.Request) bool {
	if !apiKeyMutationOriginAllowed(r.Header.Get("Origin")) {
		httpx.WriteError(w, csarerrors.Forbidden("untrusted request origin"))
		return false
	}
	return true
}

func validWBSellerID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

func (h *Handler) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := h.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	keys := h.apiKeyStore()
	if keys == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API keys unavailable"))
		return
	}
	items, err := keys.ListAPICredentials(r.Context(), user.ID)
	if err != nil {
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "max_active": maxActiveAPIKeys})
}

func (h *Handler) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if !h.checkAPIKeyMutationOrigin(w, r) {
		return
	}
	user, ok := h.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	keys := h.apiKeyStore()
	if keys == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API key issuance unavailable"))
		return
	}
	var body struct {
		credentialCallerInput
		SellerID string          `json:"seller_id"`
		Label    string          `json:"label"`
		Scopes   json.RawMessage `json:"scopes"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || !validWBSellerID(body.SellerID) {
		httpx.WriteError(w, csarerrors.Validation("valid seller_id and label are required"))
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		httpx.WriteError(w, csarerrors.Validation("one JSON object is required"))
		return
	}
	body.Label = strings.TrimSpace(body.Label)
	if body.Label == "" || len([]rune(body.Label)) > 80 {
		httpx.WriteError(w, csarerrors.Validation("label must be 1-80 characters"))
		return
	}
	scopes, err := requestedAPIKeyScopes(body.Scopes)
	if err != nil {
		httpx.WriteError(w, csarerrors.Validation("%s", err))
		return
	}
	if !h.allowSellerScopes(w, r, user.ID, body.SellerID, scopes) {
		return
	}
	prefix := apiKeyPrefix
	if slices.Contains(scopes, store.APIKeyScopeAnalyticsRead) || slices.Contains(scopes, store.APIKeyScopeAdvertisingRead) {
		prefix = apiKeyScopedPrefix
	}
	raw := prefix + randomToken()

	newCaller, err := body.newCaller(user.ID, body.Label)
	if err != nil {
		httpx.WriteError(w, csarerrors.Validation("%s", err))
		return
	}
	key := &store.APICredential{
		NewCaller: newCaller,
		ID:        uuid.New(), OwnerID: user.ID, CallerID: body.CallerID, SellerID: body.SellerID, Label: body.Label,
		TokenHash: hashValue(raw), Prefix: raw[:len(prefix)+8], Scopes: scopes,
		ExpiresAt: time.Now().UTC().Add(apiKeyLifetime),
	}
	if err := keys.CreateAPICredential(r.Context(), key, maxActiveAPIKeys); err != nil {
		if errors.Is(err, store.ErrCallerLimit) {
			httpx.WriteError(w, csarerrors.Conflict("active caller limit reached; reuse or revoke a caller"))
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, csarerrors.NotFound("caller not found"))
			return
		}
		if errors.Is(err, store.ErrCallerAuditRequired) {
			httpx.WriteError(w, csarerrors.Unavailable("caller audit unavailable"))
			return
		}
		if errors.Is(err, store.ErrAPICredentialLimit) {
			httpx.WriteError(w, csarerrors.Conflict("active API key limit reached"))
			return
		}
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"key": key, "token": raw})
	h.recordAPIKeyAudit(r, user.ID.String(), "api_key.create", key)
}

func (h *Handler) allowSellerScopes(w http.ResponseWriter, r *http.Request, owner uuid.UUID, seller string, scopes []string) bool {
	for _, scope := range scopes {
		action := "massAdvert.read"
		if scope == store.APIKeyScopeAnalyticsRead {
			action = "analytics.read"
		}
		allowed, err := h.checkSellerAction(r, owner, seller, action)
		if err != nil {
			httpx.WriteError(w, csarerrors.Unavailable("authorization unavailable"))
			return false
		}
		if !allowed {
			httpx.WriteError(w, csarerrors.Forbidden("%s access required", scope))
			return false
		}
	}
	return true
}

func (h *Handler) checkSellerAction(r *http.Request, owner uuid.UUID, seller, action string) (bool, error) {
	if h.authzClient == nil {
		return false, errors.New("authorization unavailable")
	}
	access, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject: owner.String(), Resource: "campaign_module", Action: action,
		ScopeType: "tenant", ScopeId: "wildberries:" + seller,
	})
	if err != nil || access == nil {
		return false, errors.New("authorization unavailable")
	}
	return access.Allowed, nil
}

func requestedAPIKeyScopes(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{store.APIKeyScopeAdvertsRead}, nil
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, errors.New("scopes must be an array of read scope names")
	}
	if err := store.ValidateAPICredentialScopes(scopes); err != nil {
		return nil, err
	}
	slices.Sort(scopes)
	return scopes, nil
}

func validAPIKeyFormat(token string) bool {
	return strings.HasPrefix(token, apiKeyPrefix) && len(token) == len(apiKeyPrefix)+43 ||
		strings.HasPrefix(token, apiKeyScopedPrefix) && len(token) == len(apiKeyScopedPrefix)+43
}

func (h *Handler) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if !h.checkAPIKeyMutationOrigin(w, r) {
		return
	}
	user, ok := h.sellerCredentialOwner(w, r)
	if !ok {
		return
	}
	keyID, err := uuid.Parse(r.PathValue("key_id"))
	if err != nil {
		httpx.WriteError(w, csarerrors.Validation("invalid key_id"))
		return
	}
	keys := h.apiKeyStore()
	if keys == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API keys unavailable"))
		return
	}
	key, err := keys.RevokeAPICredential(r.Context(), user.ID, keyID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, csarerrors.NotFound("API key not found"))
			return
		}
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	h.recordAPIKeyAudit(r, user.ID.String(), "api_key.revoke", key)
}

func (h *Handler) handleIntrospectAPIKey(w http.ResponseWriter, r *http.Request) {
	// This endpoint has no public CSAR route and the authn server requires
	// mTLS. In particular, it never accepts a personal key as caller auth.
	if !h.verifiedServiceRouter(r.TLS) {
		httpx.WriteError(w, csarerrors.Forbidden("mTLS required"))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		!validAPIKeyFormat(body.Token) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	keys := h.apiKeyStore()
	if keys == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API keys unavailable"))
		return
	}

	key, err := keys.FindAPICredentialByHash(r.Context(), hashValue(body.Token))
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	if key == nil || store.ValidateAPICredentialScopes(key.Scopes) != nil {
		httpx.WriteError(w, csarerrors.Unavailable("API key scope data unavailable"))
		return
	}
	if key.CallerID != nil {
		if _, ok := h.store.(store.CallerCredentialStore); !ok {
			httpx.WriteError(w, csarerrors.Unavailable("caller binding unavailable"))
			return
		}
	}
	identity, err := h.credentialIdentity(r.Context(), key.OwnerID, caller.APIKey, key.ID.String())
	if errors.Is(err, errCallerRevoked) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		httpx.WriteError(w, csarerrors.Unavailable("caller binding unavailable"))
		return
	}
	if key.CallerID != nil && identity.CallerID != key.CallerID.String() {
		httpx.WriteError(w, csarerrors.Unavailable("caller binding unavailable"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"identity": identity,
		"active":   true, "subject": key.OwnerID.String(), "credential_id": key.ID.String(),
		"seller_id": key.SellerID, "scopes": key.Scopes,
		"expires_at": key.ExpiresAt,
	})
}

func (h *Handler) recordAPIKeyAudit(r *http.Request, actor, action string, key *store.APICredential) {
	if h.auditRecorder == nil || h.transactionalAudit(action) {
		return
	}
	h.recordAuditEvent(r, &audit.Event{
		Actor: actor, Action: action, TargetType: "api_key", TargetID: key.ID.String(),
		ScopeType: "tenant", ScopeID: "wildberries:" + key.SellerID,
	})
}
