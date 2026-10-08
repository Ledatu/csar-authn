package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	csarerrors "github.com/ledatu/csar-core/errors"
	"github.com/ledatu/csar-core/httpx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const maxActiveAPIKeys = 5
const apiKeyLifetime = 90 * 24 * time.Hour
const apiKeyPrefix = "aurum_pat_"

func (h *Handler) apiKeyStore() store.APICredentialStore {
	keys, _ := h.store.(store.APICredentialStore)
	return keys
}

func (h *Handler) sessionAPIKeyUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	// Key lifecycle is cookie-session only. Even a valid user JWT must not mint
	// or revoke personal keys through this surface.
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
	user, ok := h.sessionAPIKeyUser(w, r)
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
	user, ok := h.sessionAPIKeyUser(w, r)
	if !ok {
		return
	}
	keys := h.apiKeyStore()
	if keys == nil || h.authzClient == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API key issuance unavailable"))
		return
	}
	var body struct {
		SellerID string `json:"seller_id"`
		Label    string `json:"label"`
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
	access, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject: user.ID.String(), Resource: "campaign_module", Action: "massAdvert.read",
		ScopeType: "tenant", ScopeId: "wildberries:" + body.SellerID,
	})
	if err != nil {
		httpx.WriteError(w, csarerrors.Unavailable("authorization unavailable"))
		return
	}
	if !access.Allowed {
		httpx.WriteError(w, csarerrors.Forbidden("advert read access required"))
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	raw := apiKeyPrefix + base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(raw))
	key := &store.APICredential{
		ID: uuid.New(), OwnerID: user.ID, SellerID: body.SellerID, Label: body.Label,
		TokenHash: hex.EncodeToString(digest[:]), Prefix: raw[:len(apiKeyPrefix)+8],
		ExpiresAt: time.Now().UTC().Add(apiKeyLifetime),
	}
	if err := keys.CreateAPICredential(r.Context(), key, maxActiveAPIKeys); err != nil {
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

func (h *Handler) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if !h.checkAPIKeyMutationOrigin(w, r) {
		return
	}
	user, ok := h.sessionAPIKeyUser(w, r)
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
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
		r.TLS.PeerCertificates[0].Subject.CommonName != "csar-client" {
		httpx.WriteError(w, csarerrors.Forbidden("mTLS required"))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		!strings.HasPrefix(body.Token, apiKeyPrefix) || len(body.Token) != len(apiKeyPrefix)+43 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	keys := h.apiKeyStore()
	if keys == nil {
		httpx.WriteError(w, csarerrors.Unavailable("API keys unavailable"))
		return
	}
	digest := sha256.Sum256([]byte(body.Token))
	key, err := keys.FindAPICredentialByHash(r.Context(), hex.EncodeToString(digest[:]))
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"active": true, "subject": key.OwnerID.String(), "credential_id": key.ID.String(),
		"seller_id": key.SellerID, "scopes": []string{"adverts:read"},
		"expires_at": key.ExpiresAt,
	})
}

func (h *Handler) recordAPIKeyAudit(r *http.Request, actor, action string, key *store.APICredential) {
	if h.auditRecorder == nil || h.transactionalAudit(action) {
		return
	}
	if err := h.auditRecorder.Record(r.Context(), &audit.Event{
		Actor: actor, Action: action, TargetType: "api_key", TargetID: key.ID.String(),
		ScopeType: "tenant", ScopeID: "wildberries:" + key.SellerID,
	}); err != nil {
		h.logger.Warn("API key audit failed", "action", action, "error", err)
	}
}
