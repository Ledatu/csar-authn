package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/identityimport"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
)

func (h *Handler) handleIdentityImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	policy := h.cfg.Load().IdentityImport
	if policy == nil || !policy.Enabled {
		credentialError(w, 404)
		return
	}
	if !h.verifiedGeneralPeer(r.TLS, policy.RouterPeerCN) {
		credentialError(w, 403)
		return
	}
	actor := r.Header.Get(gatewayctx.HeaderSubject)
	var req identityimport.Request
	if httpx.ReadStrictJSON(r, &req) != nil {
		credentialError(w, 400)
		return
	}
	importer, ok := policy.Importers[req.Importer]
	if !ok || actor != importer.Subject || req.Source != importer.Source {
		credentialError(w, 403)
		return
	}
	query := r.URL.Query()
	if len(query["dry_run"]) > 1 || len(query["actions"]) > 1 {
		credentialError(w, 400)
		return
	}
	for key := range query {
		if key != "dry_run" && key != "actions" {
			credentialError(w, 400)
			return
		}
	}
	apply := false
	switch query.Get("dry_run") {
	case "", "true":
	case "false":
		apply = true
	default:
		credentialError(w, 400)
		return
	}
	actions := []string(nil)
	if raw := query.Get("actions"); raw != "" {
		actions = strings.Split(raw, ",")
	}
	if !apply && len(actions) > 0 {
		credentialError(w, 400)
		return
	}
	st, ok := h.store.(identityimport.Store)
	if !ok {
		credentialError(w, 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	// Preserve only router-asserted request context for transactional audit.
	id, _ := gatewayctx.FromContext(ctx)
	id.Subject = actor
	ctx = gatewayctx.NewContext(ctx, &id)
	report, err := identityimport.Run(ctx, st, &req, importer, actor, apply, actions)
	switch {
	case errors.Is(err, identityimport.ErrInvalid):
		credentialError(w, 400)
	case errors.Is(err, identityimport.ErrBusy):
		credentialError(w, 409)
	case err != nil:
		credentialError(w, 503)
	default:
		httpx.WriteJSON(w, 200, report)
	}
}
