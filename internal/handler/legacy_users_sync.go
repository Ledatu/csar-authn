package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/gatewayctx"

	"github.com/ledatu/csar-authn/internal/legacysync"
)

const maxLegacyUsersSyncBodyBytes = 16 << 20

// handleLegacyUsersSync plans the legacy Mongo users into authn. Only dry runs
// exist: nothing is written.
func (h *Handler) handleLegacyUsersSync(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load().LegacyUsersSync
	if !cfg.Enabled {
		apierror.New("not_found", http.StatusNotFound, "not found").Write(w)
		return
	}
	subject := r.Header.Get(gatewayctx.HeaderSubject)
	if !slices.Contains(cfg.AllowedSubjects, subject) {
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "forbidden").Write(w)
		return
	}
	if r.URL.Query().Get("dry_run") != "true" {
		apierror.New("bad_request", http.StatusBadRequest, "only dry_run=true is supported").Write(w)
		return
	}

	var req legacysync.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLegacyUsersSyncBodyBytes)).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	report, err := h.legacyUsersSync.DryRun(r.Context(), &req, legacysync.Options{
		MaxUsers:  cfg.MaxUsers,
		Overrides: cfg.IdentityOverrides,
	})
	switch {
	case errors.Is(err, legacysync.ErrInvalidRequest):
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	case err != nil:
		h.logger.Error("legacy users sync dry run failed", "subject", subject, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "legacy users sync failed").Write(w)
		return
	}

	s := report.Summary
	h.logger.Info("legacy users sync dry run",
		"subject", subject,
		"users", s.Users,
		"create", s.Create,
		"link", s.Link,
		"split_identity", s.SplitIdentity,
		"blocked", s.Blocked,
		"synthetic_telegram_rows", s.SyntheticTelegramRows,
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(report)
}
