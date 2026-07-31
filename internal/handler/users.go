package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const (
	permAdminUserLookup       = "platform.roles.assign"
	defaultAdminUserListLimit = 20
	maxAdminUserListLimit     = 50
	minAdminUserQueryLength   = 2
	maxServiceUserResolveIDs  = 100
	// maxBrowserUserResolveIDs bounds one browser batch. It caps the worst-case
	// avatar signing work per request and keeps the body small; clients chunk.
	maxBrowserUserResolveIDs = 200
	// avatarResolveConcurrency bounds simultaneous csar-s3 signing calls for a
	// single batch, so a cold cache cannot fan out one round trip per user.
	avatarResolveConcurrency = 8
)

// browserResolvableProviders restricts directory lookups to providers the seller
// UI actually renders. Without this the endpoint becomes a generic identity
// oracle over every linked OAuth account.
var browserResolvableProviders = map[string]struct{}{
	"telegram": {},
}

type adminUserListItem struct {
	ID               string `json:"id"`
	Email            string `json:"email,omitempty"`
	DisplayName      string `json:"display_name"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	AvatarPreviewURL string `json:"avatar_preview_url,omitempty"`
}

type adminUserListResponse struct {
	Users []adminUserListItem `json:"users"`
	Limit int                 `json:"limit"`
}

type serviceUserResolveRequest struct {
	IDs []string `json:"ids"`
}

type serviceUserResolveItem struct {
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	AvatarPreviewURL string `json:"avatar_preview_url,omitempty"`
}

type serviceUserResolveResponse struct {
	Users []serviceUserResolveItem `json:"users"`
}

func (h *Handler) requireAdminUserLookupPermission(r *http.Request, subject string) *apierror.Response {
	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		ScopeType: "platform",
		Resource:  "admin",
		Action:    permAdminUserLookup,
	})
	if err != nil {
		h.logger.Error("authz check failed", "subject", subject, "action", permAdminUserLookup, "error", err)
		return apierror.New("authz_error", http.StatusBadGateway, "authorization check failed")
	}
	if !resp.Allowed {
		return apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "insufficient permissions")
	}
	return nil
}

func (h *Handler) handleListAdminUsers(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if apiErr := h.requireAdminUserLookupPermission(r, subject); apiErr != nil {
		apiErr.Write(w)
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		apierror.New("bad_request", http.StatusBadRequest, "q is required").Write(w)
		return
	}
	if len([]rune(query)) < minAdminUserQueryLength && !looksLikeUUID(query) {
		apierror.New("bad_request", http.StatusBadRequest, "q must be at least 2 characters or a user ID").Write(w)
		return
	}

	limit := defaultAdminUserListLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			apierror.New("bad_request", http.StatusBadRequest, "invalid limit").Write(w)
			return
		}
		limit = n
	}
	if limit > maxAdminUserListLimit {
		limit = maxAdminUserListLimit
	}

	users, err := h.store.SearchUsers(r.Context(), store.UserSearchParams{
		Query: query,
		Limit: limit,
	})
	if err != nil {
		h.logger.Error("failed to search users", "query", query, "limit", limit, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to search users").Write(w)
		return
	}

	resp := adminUserListResponse{
		Users: make([]adminUserListItem, len(users)),
		Limit: limit,
	}
	for i := range users {
		avatarURL, avatarPreviewURL := h.resolveAvatarURLs(r.Context(), users[i].AvatarStorageKey, users[i].AvatarPreviewStorageKey, users[i].AvatarURL)
		resp.Users[i] = adminUserListItem{
			ID:               users[i].ID.String(),
			Email:            users[i].Email,
			DisplayName:      users[i].DisplayName,
			AvatarURL:        avatarURL,
			AvatarPreviewURL: avatarPreviewURL,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization, Cookie")
	_ = json.NewEncoder(w).Encode(resp)
}

func looksLikeUUID(v string) bool {
	_, err := uuid.Parse(v)
	return err == nil
}

func (h *Handler) handleResolveServiceUsers(w http.ResponseWriter, r *http.Request) {
	var req serviceUserResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	ids := dedupeValidUserIDs(req.IDs, maxServiceUserResolveIDs)
	if len(ids) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(serviceUserResolveResponse{Users: []serviceUserResolveItem{}})
		return
	}

	users, err := h.resolveUsersByID(r.Context(), ids)
	if err != nil {
		h.logger.Error("failed to resolve service users", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to resolve users").Write(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization")
	_ = json.NewEncoder(w).Encode(serviceUserResolveResponse{Users: users})
}

func (h *Handler) resolveUsersByID(ctx context.Context, ids []uuid.UUID) ([]serviceUserResolveItem, error) {
	resolved, err := h.store.GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	byRequested := make(map[uuid.UUID]store.ResolvedUser, len(resolved))
	for _, r := range resolved {
		byRequested[r.RequestedID] = r
	}

	out := make([]serviceUserResolveItem, 0, len(resolved))
	for _, id := range ids {
		r, ok := byRequested[id]
		if !ok {
			continue
		}
		avatarURL, avatarPreviewURL := h.resolveAvatarURLs(ctx, r.AvatarStorageKey, r.AvatarPreviewStorageKey, r.AvatarURL)
		out = append(out, serviceUserResolveItem{
			// Echo the requested id, not the canonical one. Consumers key this
			// response by the id they asked for; a merged account would
			// otherwise resolve to an id they never sent and drop out of their map.
			ID:               id.String(),
			DisplayName:      r.DisplayName,
			AvatarURL:        avatarURL,
			AvatarPreviewURL: avatarPreviewURL,
		})
	}
	return out, nil
}

type browserUserResolveRequest struct {
	Provider string   `json:"provider"`
	IDs      []string `json:"ids"`
}

// browserUserItem is deliberately free of email, phone, and linked accounts.
// Any authenticated seller can call this, so it carries only what a member card
// renders.
type browserUserItem struct {
	ID               string `json:"id"`
	Provider         string `json:"provider"`
	ProviderUserID   string `json:"provider_user_id"`
	DisplayName      string `json:"display_name"`
	Username         string `json:"username,omitempty"`
	AvatarURL        string `json:"avatar_url,omitempty"`
	AvatarPreviewURL string `json:"avatar_preview_url,omitempty"`
}

type browserUserResolveResponse struct {
	Users []browserUserItem `json:"users"`
}

type browserUserLookupRequest struct {
	Identifier string `json:"identifier"`
}

type browserUserLookupResponse struct {
	User browserUserItem `json:"user"`
}

func (h *Handler) handleResolveBrowserUsers(w http.ResponseWriter, r *http.Request) {
	if h.extractSubject(r) == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	var req browserUserResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	provider := strings.TrimSpace(strings.ToLower(req.Provider))
	if _, ok := browserResolvableProviders[provider]; !ok {
		apierror.New("bad_request", http.StatusBadRequest, "unsupported provider").Write(w)
		return
	}

	// Reject rather than truncate. Silently dropping the tail of a batch renders
	// as blank member cards with no signal to the client.
	if len(req.IDs) > maxBrowserUserResolveIDs {
		apierror.New("bad_request", http.StatusBadRequest,
			fmt.Sprintf("at most %d ids per request", maxBrowserUserResolveIDs)).Write(w)
		return
	}

	ids := dedupeProviderUserIDs(req.IDs)
	if len(ids) == 0 {
		writeBrowserUsers(w, []browserUserItem{})
		return
	}

	users, err := h.store.GetUsersByProviderIDs(r.Context(), provider, ids)
	if err != nil {
		h.logger.Error("failed to resolve browser users", "provider", provider, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to resolve users").Write(w)
		return
	}

	writeBrowserUsers(w, h.browserUserItems(r.Context(), provider, users))
}

func (h *Handler) handleLookupBrowserUser(w http.ResponseWriter, r *http.Request) {
	if h.extractSubject(r) == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	var req browserUserLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		apierror.New("bad_request", http.StatusBadRequest, "identifier is required").Write(w)
		return
	}

	item, found, err := h.lookupBrowserUser(r.Context(), identifier)
	if err != nil {
		h.logger.Error("failed to look up browser user", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to look up user").Write(w)
		return
	}
	if !found {
		apierror.New("not_found", http.StatusNotFound, "user not found").Write(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	_ = json.NewEncoder(w).Encode(browserUserLookupResponse{User: item})
}

// lookupBrowserUser resolves exactly one identifier: either an internal user
// UUID or a numeric Telegram id. Matching is exact by design — no prefix or
// substring search, so this cannot be walked to enumerate the user base.
func (h *Handler) lookupBrowserUser(ctx context.Context, identifier string) (browserUserItem, bool, error) {
	const telegramProvider = "telegram"

	if id, err := uuid.Parse(identifier); err == nil {
		resolved, err := h.store.GetUsersByIDs(ctx, []uuid.UUID{id})
		if err != nil || len(resolved) == 0 {
			return browserUserItem{}, false, err
		}
		user := resolved[0].User

		// Surface the telegram link when there is one; the caller needs it to
		// talk to the legacy member endpoints.
		providerUserID, metadata := h.telegramLink(ctx, user.ID)
		return h.browserUserItem(ctx, telegramProvider, &store.ProviderUser{
			User:             user,
			ProviderUserID:   providerUserID,
			ProviderMetadata: metadata,
		}), true, nil
	}

	if !isNumericIdentifier(identifier) {
		return browserUserItem{}, false, nil
	}

	users, err := h.store.GetUsersByProviderIDs(ctx, telegramProvider, []string{identifier})
	if err != nil || len(users) == 0 {
		return browserUserItem{}, false, err
	}
	return h.browserUserItem(ctx, telegramProvider, &users[0]), true, nil
}

func (h *Handler) telegramLink(ctx context.Context, userID uuid.UUID) (string, map[string]interface{}) {
	accounts, err := h.store.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return "", nil
	}
	for i := range accounts {
		if accounts[i].Provider == "telegram" {
			return accounts[i].ProviderUserID, accounts[i].ProviderMetadata
		}
	}
	return "", nil
}

// browserUserItems resolves a batch with bounded parallelism. The avatar cache
// removes the steady-state cost of signing, but a cold cache over a full batch
// would otherwise serialize one csar-s3 round trip per storage key.
func (h *Handler) browserUserItems(ctx context.Context, provider string, users []store.ProviderUser) []browserUserItem {
	out := make([]browserUserItem, len(users))

	sem := make(chan struct{}, avatarResolveConcurrency)
	var wg sync.WaitGroup
	for i := range users {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = h.browserUserItem(ctx, provider, &users[i])
		}(i)
	}
	wg.Wait()

	return out
}

func (h *Handler) browserUserItem(ctx context.Context, provider string, u *store.ProviderUser) browserUserItem {
	avatarURL, avatarPreviewURL := h.resolveAvatarURLs(ctx, u.AvatarStorageKey, u.AvatarPreviewStorageKey, u.AvatarURL)
	return browserUserItem{
		ID:               u.ID.String(),
		Provider:         provider,
		ProviderUserID:   u.ProviderUserID,
		DisplayName:      u.DisplayName,
		Username:         providerUsername(u.ProviderMetadata),
		AvatarURL:        avatarURL,
		AvatarPreviewURL: avatarPreviewURL,
	}
}

// providerUsername reads the Telegram handle captured by the legacy JWT bridge.
// Most accounts predate that path and have none, in which case callers fall back
// to identifiers.
func providerUsername(metadata map[string]interface{}) string {
	raw, ok := metadata["legacy_username"]
	if !ok {
		return ""
	}
	username, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(username), "@")
}

func isNumericIdentifier(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func writeBrowserUsers(w http.ResponseWriter, users []browserUserItem) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	_ = json.NewEncoder(w).Encode(browserUserResolveResponse{Users: users})
}

func dedupeProviderUserIDs(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		id := strings.TrimSpace(item)
		if !isNumericIdentifier(id) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}

	return out
}

func dedupeValidUserIDs(raw []string, limit int) []uuid.UUID {
	if len(raw) == 0 || limit <= 0 {
		return nil
	}

	seen := make(map[uuid.UUID]struct{}, len(raw))
	out := make([]uuid.UUID, 0, min(limit, len(raw)))
	for _, item := range raw {
		if len(out) >= limit {
			break
		}

		id, err := uuid.Parse(strings.TrimSpace(item))
		if err != nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}

	return out
}
