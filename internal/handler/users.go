package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

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
)

type adminUserListItem struct {
	ID          string `json:"id"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url,omitempty"`
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
	AvatarURL   string `json:"avatar_url,omitempty"`
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
		resp.Users[i] = adminUserListItem{
			ID:          users[i].ID.String(),
			Email:       users[i].Email,
			DisplayName: users[i].DisplayName,
			AvatarURL:   h.resolveAvatarURL(r.Context(), users[i].AvatarStorageKey, users[i].AvatarURL),
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
	out := make([]serviceUserResolveItem, 0, len(ids))
	for _, id := range ids {
		user, err := h.store.GetUserByID(ctx, id)
		if err != nil {
			if err == store.ErrNotFound {
				continue
			}
			return nil, err
		}
		out = append(out, serviceUserResolveItem{
			ID:          user.ID.String(),
			DisplayName: user.DisplayName,
			AvatarURL:   h.resolveAvatarURL(ctx, user.AvatarStorageKey, user.AvatarURL),
		})
	}
	return out, nil
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
