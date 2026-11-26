package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/httpx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

const (
	permAdminUserLookup       = "platform.roles.assign"
	defaultAdminUserListLimit = 20
	maxAdminUserListLimit     = 50
	minAdminUserQueryLength   = 2
	maxServiceUserResolveIDs  = 100
	// maxBrowserUserResolveIDs bounds response size; clients chunk larger batches.
	maxBrowserUserResolveIDs = 200
)

type adminUserListItem struct {
	ID          string `json:"id"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name"`
}

type adminUserListResponse struct {
	Users []adminUserListItem `json:"users"`
	Limit int                 `json:"limit"`
}

type serviceUserResolveRequest struct {
	IDs []string `json:"ids"`
}

type serviceUserResolveItem struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
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
	subject, apiErr := h.adminAuth(r)
	if apiErr != nil {
		apiErr.Write(w)
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
		resp.Users[i] = adminUserListItem{
			ID:          users[i].ID.String(),
			Email:       users[i].Email,
			DisplayName: users[i].DisplayName,
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
	if err := readDirectoryJSON(w, r, &req); err != nil {
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
		out = append(out, serviceUserResolveItem{
			// Echo the requested id, not the canonical one. Consumers key this
			// response by the id they asked for; a merged account would
			// otherwise resolve to an id they never sent and drop out of their map.
			ID:          id.String(),
			DisplayName: r.DisplayName,
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
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	DisplayName    string `json:"display_name"`
	Username       string `json:"username,omitempty"`
}

type browserUserResolveResponse struct {
	Users []browserUserItem `json:"users"`
}

type browserUserLookupRequest struct {
	Identifier string `json:"identifier"`
	Provider   string `json:"provider,omitempty"`
	Projection string `json:"projection,omitempty"`
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
	if err := readDirectoryJSON(w, r, &req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	provider, allowed := h.cfg.Load().BrowserDirectory.ResolveProvider(strings.TrimSpace(strings.ToLower(req.Provider)))
	if !allowed {
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

	if provider == "subject" {
		h.resolveBrowserUsersByID(w, r, req.IDs)
		return
	}

	ids := h.directoryIDs(provider, req.IDs)
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

func (h *Handler) resolveBrowserUsersByID(w http.ResponseWriter, r *http.Request, rawIDs []string) {
	ids := dedupeValidUserIDs(rawIDs, maxBrowserUserResolveIDs)
	if len(ids) == 0 {
		writeBrowserUsers(w, []browserUserItem{})
		return
	}

	resolved, err := h.store.GetUsersByIDs(r.Context(), ids)
	if err != nil {
		h.logger.Error("failed to resolve browser users", "provider", "subject", "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "failed to resolve users").Write(w)
		return
	}

	users := make([]store.ProviderUser, 0, len(resolved))
	for i := range resolved {
		// Echo the requested id as provider_user_id so clients key by what they sent,
		// even when the account was merged into another user.
		users = append(users, store.ProviderUser{
			User:           resolved[i].User,
			ProviderUserID: resolved[i].RequestedID.String(),
		})
	}

	writeBrowserUsers(w, h.browserUserItems(r.Context(), "subject", users))
}

func (h *Handler) handleLookupBrowserUser(w http.ResponseWriter, r *http.Request) {
	if h.extractSubject(r) == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	var req browserUserLookupRequest
	if err := readDirectoryJSON(w, r, &req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		apierror.New("bad_request", http.StatusBadRequest, "identifier is required").Write(w)
		return
	}

	provider, allowed := h.cfg.Load().BrowserDirectory.ResolveProvider(req.Provider)
	if !allowed {
		apierror.New("bad_request", 400, "unsupported provider").Write(w)
		return
	}
	projectionProvider := ""
	if req.Projection != "" {
		directory := h.cfg.Load().BrowserDirectory
		if directory != nil {
			projectionProvider = directory.Projections[req.Projection]
		}
		if projectionProvider == "" || provider != "subject" {
			apierror.New("bad_request", 400, "unsupported projection").Write(w)
			return
		}
	}
	item, found, err := h.lookupDirectoryUser(r.Context(), provider, projectionProvider, identifier)
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

// lookupDirectoryUser resolves only exact IDs under explicit projection policy.
func (h *Handler) lookupDirectoryUser(ctx context.Context, provider, projection, identifier string) (browserUserItem, bool, error) {
	if provider != "subject" {
		ids := h.directoryIDs(provider, []string{identifier})
		if len(ids) == 0 {
			return browserUserItem{}, false, nil
		}
		users, err := h.store.GetUsersByProviderIDs(ctx, provider, ids)
		if err != nil || len(users) == 0 {
			return browserUserItem{}, false, err
		}
		return h.browserUserItem(ctx, provider, &users[0]), true, nil
	}
	id, err := uuid.Parse(identifier)
	if err != nil || id == uuid.Nil {
		return browserUserItem{}, false, nil
	}
	users, err := h.store.GetUsersByIDs(ctx, []uuid.UUID{id})
	if err != nil || len(users) == 0 {
		return browserUserItem{}, false, err
	}
	u := store.ProviderUser{User: users[0].User, ProviderUserID: users[0].RequestedID.String()}
	if projection == "" {
		return h.browserUserItem(ctx, "subject", &u), true, nil
	}
	accounts, err := h.store.GetOAuthAccountsByUserID(ctx, u.ID)
	if err != nil {
		return browserUserItem{}, false, err
	}
	for i := range accounts {
		if accounts[i].Provider == projection {
			u.ProviderUserID = accounts[i].ProviderUserID
			u.ProviderMetadata = accounts[i].ProviderMetadata
			return h.browserUserItem(ctx, projection, &u), true, nil
		}
	}
	return browserUserItem{}, false, nil
}

func readDirectoryJSON(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	return httpx.ReadStrictJSON(r, out)
}

func (h *Handler) directoryIDs(provider string, raw []string) []string {
	directory := h.cfg.Load().BrowserDirectory
	if directory == nil {
		return nil
	}
	rule, ok := directory.Providers[provider]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if !authnconfig.ValidIdentityValue(id, 256) || rule.IDFormat == "numeric" && !isNumericIdentifier(id) || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (h *Handler) browserUserItems(ctx context.Context, provider string, users []store.ProviderUser) []browserUserItem {
	out := make([]browserUserItem, len(users))
	for i := range users {
		out[i] = h.browserUserItem(ctx, provider, &users[i])
	}
	return out
}

func (h *Handler) browserUserItem(ctx context.Context, provider string, u *store.ProviderUser) browserUserItem {
	return browserUserItem{
		ID:             u.ID.String(),
		Provider:       provider,
		ProviderUserID: u.ProviderUserID,
		DisplayName:    u.DisplayName,
		Username:       h.directoryUsername(provider, u.ProviderMetadata),
	}
}

func (h *Handler) directoryUsername(provider string, metadata map[string]interface{}) string {
	directory := h.cfg.Load().BrowserDirectory
	if directory == nil {
		return ""
	}
	key := directory.Providers[provider].UsernameMetadataKey
	if key == "" {
		return ""
	}
	username, _ := metadata[key].(string)
	if !authnconfig.ValidIdentityValue(username, 128) {
		return ""
	}
	return strings.TrimPrefix(username, "@")
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
