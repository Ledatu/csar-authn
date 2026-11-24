package handler

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
	csarerrors "github.com/ledatu/csar-core/errors"
	"github.com/ledatu/csar-core/httpx"
)

const maxActiveCallers = store.DefaultCallerLimit

func (h *Handler) callerRegistry(w http.ResponseWriter, r *http.Request, mutation bool) (store.CallerRegistryStore, *store.User, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if mutation && !h.checkAPIKeyMutationOrigin(w, r) {
		return nil, nil, false
	}
	u, ok := h.sellerCredentialOwner(w, r)
	if !ok {
		return nil, nil, false
	}
	registry, ok := h.store.(store.CallerRegistryStore)
	if !ok {
		httpx.WriteError(w, csarerrors.Unavailable("caller registry unavailable"))
		return nil, nil, false
	}
	return registry, u, true
}

func (h *Handler) handleCreateCaller(w http.ResponseWriter, r *http.Request) {
	registry, u, ok := h.callerRegistry(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Kind  caller.Kind `json:"caller_kind"`
		Label string      `json:"label"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := httpx.ReadJSON(r, &body); err != nil {
		httpx.WriteError(w, err)
		return
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: body.Kind, Label: body.Label}
	if err := c.ValidateRegistration(); err != nil {
		httpx.WriteError(w, csarerrors.Validation("%s", err))
		return
	}
	if err := registry.CreateCaller(r.Context(), c, maxActiveCallers); err != nil {
		switch {
		case errors.Is(err, store.ErrCallerLimit):
			httpx.WriteError(w, csarerrors.Conflict("active caller limit reached"))
		case errors.Is(err, store.ErrCallerAuditRequired):
			httpx.WriteError(w, csarerrors.Unavailable("caller audit unavailable"))
		default:
			httpx.WriteError(w, csarerrors.Internal(err))
		}
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (h *Handler) handleListCallers(w http.ResponseWriter, r *http.Request) {
	registry, u, ok := h.callerRegistry(w, r, false)
	if !ok {
		return
	}
	items, err := registry.ListActiveCallers(r.Context(), u.ID)
	if err != nil {
		httpx.WriteError(w, csarerrors.Internal(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "status": "active", "max_active": maxActiveCallers})
}

func (h *Handler) handleRevokeCaller(w http.ResponseWriter, r *http.Request) {
	registry, u, ok := h.callerRegistry(w, r, true)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("caller_id"))
	if err != nil || id == uuid.Nil {
		httpx.WriteError(w, csarerrors.Validation("valid caller_id required"))
		return
	}
	if _, err := registry.RevokeCaller(r.Context(), u.ID, id); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			httpx.WriteError(w, csarerrors.NotFound("caller not found"))
		case errors.Is(err, store.ErrCallerAuditRequired):
			httpx.WriteError(w, csarerrors.Unavailable("caller audit unavailable"))
		default:
			httpx.WriteError(w, csarerrors.Internal(err))
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
