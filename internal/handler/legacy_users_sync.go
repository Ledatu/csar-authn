package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/gatewayctx"

	"github.com/ledatu/csar-authn/internal/legacysync"
)

const maxLegacyUsersSyncBodyBytes = 16 << 20

// handleLegacyUsersSync plans the legacy Mongo users into authn and, with
// dry_run=false, writes the actions both the request and the config allow.
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
	dryRun := r.URL.Query().Get("dry_run")
	if dryRun != "true" && dryRun != "false" {
		apierror.New("bad_request", http.StatusBadRequest, "dry_run must be true or false").Write(w)
		return
	}
	var actions []legacysync.Action
	if dryRun == "false" {
		if !cfg.Apply.Enabled {
			apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "legacy users sync apply is disabled").Write(w)
			return
		}
		if actions = allowedLegacyActions(r.URL.Query().Get("actions"), cfg.Apply.Actions); len(actions) == 0 {
			apierror.New("bad_request", http.StatusBadRequest, "no allowed actions requested").Write(w)
			return
		}
	}

	var req legacysync.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLegacyUsersSyncBodyBytes)).Decode(&req); err != nil {
		apierror.New("bad_request", http.StatusBadRequest, "invalid request body").Write(w)
		return
	}

	opts := legacysync.Options{MaxUsers: cfg.MaxUsers, Overrides: cfg.IdentityOverrides}
	var report *legacysync.Report
	var err error
	if actions == nil {
		report, err = h.legacyUsersSync.DryRun(r.Context(), &req, opts)
	} else {
		report, err = h.legacyUsersSync.Apply(r.Context(), &req, opts, legacysync.ApplyOptions{
			Actions:    actions,
			MaxLinks:   cfg.Apply.MaxLinks,
			MaxCreates: cfg.Apply.MaxCreates,
		})
	}
	switch {
	case errors.Is(err, legacysync.ErrInvalidRequest):
		apierror.New("bad_request", http.StatusBadRequest, err.Error()).Write(w)
		return
	case errors.Is(err, legacysync.ErrRunInProgress):
		apierror.New("conflict", http.StatusConflict, err.Error()).Write(w)
		return
	case err != nil:
		h.logger.Error("legacy users sync failed", "subject", subject, "dry_run", dryRun, "error", err)
		apierror.New("internal_error", http.StatusInternalServerError, "legacy users sync failed").Write(w)
		return
	}
	if report.Applied != nil {
		h.recordLegacyUsersSyncAudit(r, subject, report)
	}

	s := report.Summary
	h.logger.Info("legacy users sync",
		"subject", subject,
		"dry_run", report.DryRun,
		"users", s.Users,
		"create", s.Create,
		"link", s.Link,
		"split_identity", s.SplitIdentity,
		"blocked", s.Blocked,
		"synthetic_telegram_rows", s.SyntheticTelegramRows,
		"applied", report.Applied,
		"refused", len(report.Refused),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(report)
}

func allowedLegacyActions(requested string, allowed []string) []legacysync.Action {
	var out []legacysync.Action
	for _, a := range strings.Split(requested, ",") {
		a = strings.TrimSpace(a)
		if a != "" && slices.Contains(allowed, a) && !slices.Contains(out, legacysync.Action(a)) {
			out = append(out, legacysync.Action(a))
		}
	}
	return out
}

func (h *Handler) recordLegacyUsersSyncAudit(r *http.Request, actor string, report *legacysync.Report) {
	for _, p := range report.Users {
		if p.Applied != legacysync.AppliedOK {
			continue
		}
		state, _ := json.Marshal(map[string]any{"legacy_id": p.LegacyID, "providers": p.AddLinks, "source": "legacy_sync"})
		h.recordAudit(r, actor, "user.legacy_sync."+string(p.Action), "user", p.UserID, state)
	}
}
