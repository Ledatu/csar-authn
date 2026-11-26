// Package identityimport plans explicitly trusted provider identity imports.
// Source-specific models and ambiguity rules belong to the exporting application.
package identityimport

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/authnconfig"
)

var ErrInvalid = errors.New("invalid identity import request")
var ErrBusy = errors.New("identity import already in progress")
var ErrUnavailable = errors.New("identity import unavailable")

type Identity struct {
	Provider string `json:"provider"`
	ID       string `json:"provider_user_id"`
}
type Link struct {
	Identity
	Metadata map[string]string `json:"metadata,omitempty"`
}
type Record struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name,omitempty"`
	Identities  []Link `json:"identities"`
	// Conflict identities are checked, never imported. Their presence can only
	// remove authority, never override existing ownership or authorize linking.
	Conflicts []Identity `json:"conflict_identities,omitempty"`
	Blocked   bool       `json:"blocked,omitempty"`
	Email     string     `json:"email,omitempty"`
	Phone     string     `json:"phone,omitempty"`
}
type Request struct {
	Version     int       `json:"version"`
	Importer    string    `json:"importer"`
	Source      string    `json:"source"`
	GeneratedAt time.Time `json:"generated_at"`
	Records     []Record  `json:"records"`
}
type Plan struct {
	Key          string    `json:"key"`
	Action       string    `json:"action"`
	UserID       uuid.UUID `json:"user_id,omitempty"`
	AddProviders []string  `json:"add_providers,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Applied      string    `json:"applied,omitempty"`
}
type Report struct {
	Version int      `json:"version"`
	Source  string   `json:"source"`
	DryRun  bool     `json:"dry_run"`
	Records []Plan   `json:"records"`
	Refused []string `json:"refused,omitempty"`
}
type State struct {
	Matches           map[Identity]uuid.UUID
	Target            uuid.UUID
	TargetExists      bool
	InvalidOwnership  bool
	ExistingProviders map[string]string
	ContactConflict   bool
	ForbiddenMatch    bool
}
type Mutation struct {
	Record                  Record
	Override                uuid.UUID
	Actor, Importer, Source string
	Expected                Plan
}
type Store interface {
	ReadIdentityImportState(context.Context, Record, uuid.UUID) (State, error)
	TryIdentityImportLock(context.Context) (func(), bool, error)
	ApplyIdentityImport(context.Context, Mutation) (Plan, error)
}

func (r *Request) Validate(policy authnconfig.IdentityImporter, now time.Time) error {
	if r.Version != 1 || r.Source != policy.Source || !authnconfig.ValidIdentityValue(r.Importer, 64) || r.GeneratedAt.IsZero() || r.GeneratedAt.After(now.Add(5*time.Minute)) || len(r.Records) < 1 || len(r.Records) > policy.MaxUsers {
		return ErrInvalid
	}
	keys := map[string]bool{}
	ids := map[Identity]bool{}
	for _, record := range r.Records {
		if !authnconfig.ValidIdentityValue(record.Key, 128) || keys[record.Key] || len(record.Identities) > 16 || len(record.Conflicts) > 16 || len(record.DisplayName) > 256 || record.DisplayName != "" && !authnconfig.ValidIdentityValue(record.DisplayName, 256) || len(record.Email) > 320 || len(record.Phone) > 64 {
			return ErrInvalid
		}
		keys[record.Key] = true
		providers := map[string]bool{}
		for _, link := range record.Identities {
			if !slices.Contains(policy.Providers, link.Provider) || !authnconfig.ValidIdentityValue(link.ID, 256) || ids[link.Identity] || providers[link.Provider] || len(link.Metadata) > 8 {
				return ErrInvalid
			}
			ids[link.Identity] = true
			providers[link.Provider] = true
			for key, value := range link.Metadata {
				if !authnconfig.ValidIdentityValue(key, 64) || !authnconfig.ValidIdentityValue(value, 256) || key == "linked_by" || key == "import_source" {
					return ErrInvalid
				}
			}
		}
		for _, id := range record.Conflicts {
			if !slices.Contains(policy.Providers, id.Provider) || !authnconfig.ValidIdentityValue(id.ID, 256) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Decide grants no identity authority based on contact matches or caller-supplied
// target IDs. Only configured overrides may correlate an external source key.
func Decide(record Record, override uuid.UUID, st State) Plan {
	p := Plan{Key: record.Key, Action: "blocked"}
	switch {
	case record.Blocked || st.ForbiddenMatch:
		p.Reason = "source_conflict"
		return p
	case st.InvalidOwnership:
		p.Reason = "invalid_ownership"
		return p
	case len(record.Identities) == 0:
		p.Action = "no_identity"
		return p
	}
	target := uuid.Nil
	for _, id := range st.Matches {
		if target != uuid.Nil && target != id {
			p.Action = "split_identity"
			return p
		}
		target = id
	}
	if override != uuid.Nil {
		if !st.TargetExists || st.Target != override {
			p.Reason = "override_target_missing"
			return p
		}
		if target != uuid.Nil && target != override {
			p.Action = "split_identity"
			return p
		}
		p.Action = "overridden"
		p.UserID = override
		return p
	}
	if st.ContactConflict {
		p.Reason = "contact_collision"
		return p
	}
	if target != uuid.Nil && (!st.TargetExists || target != st.Target) {
		p.Reason = "target_missing"
		return p
	}
	for _, link := range record.Identities {
		if _, exists := st.Matches[link.Identity]; exists {
			continue
		}
		if existing, exists := st.ExistingProviders[link.Provider]; exists && existing != link.ID {
			p.Reason = "provider_already_linked"
			return p
		}
		p.AddProviders = append(p.AddProviders, link.Provider)
	}
	p.UserID = target
	switch {
	case target == uuid.Nil:
		p.Action = "create"
	case len(p.AddProviders) > 0:
		p.Action = "link"
	default:
		p.Action = "noop"
	}
	return p
}

func Run(ctx context.Context, st Store, req *Request, policy authnconfig.IdentityImporter, actor string, apply bool, actions []string) (*Report, error) {
	if err := req.Validate(policy, time.Now()); err != nil {
		return nil, err
	}
	if actor != policy.Subject {
		return nil, ErrInvalid
	}
	if apply {
		if !policy.Apply.Enabled || len(actions) == 0 {
			return nil, ErrInvalid
		}
		seen := map[string]bool{}
		for _, a := range actions {
			if !slices.Contains(policy.Apply.Actions, a) || seen[a] {
				return nil, ErrInvalid
			}
			seen[a] = true
		}
		release, ok, err := st.TryIdentityImportLock(ctx)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrBusy
		}
		defer release()
	}
	report := &Report{Version: 1, Source: req.Source, DryRun: !apply, Records: make([]Plan, len(req.Records))}
	counts := map[string]int{}
	for i, record := range req.Records {
		override := uuid.Nil
		if raw := policy.Overrides[record.Key]; raw != "" {
			var err error
			override, err = uuid.Parse(raw)
			if err != nil {
				return nil, ErrInvalid
			}
		}
		state, err := st.ReadIdentityImportState(ctx, record, override)
		if err != nil {
			return nil, err
		}
		report.Records[i] = Decide(record, override, state)
		counts[report.Records[i].Action]++
	}
	if !apply {
		return report, nil
	}
	caps := map[string]int{"create": policy.Apply.MaxCreates, "link": policy.Apply.MaxLinks}
	for _, a := range actions {
		if counts[a] > caps[a] {
			report.Refused = append(report.Refused, a)
		}
	}
	for i, record := range req.Records {
		p := report.Records[i]
		if !slices.Contains(actions, p.Action) || slices.Contains(report.Refused, p.Action) {
			continue
		}
		override := uuid.Nil
		if raw := policy.Overrides[record.Key]; raw != "" {
			override = uuid.MustParse(raw)
		}
		result, err := st.ApplyIdentityImport(ctx, Mutation{Record: record, Override: override, Actor: actor, Importer: req.Importer, Source: req.Source, Expected: p})
		if err != nil {
			return nil, fmt.Errorf("%w: apply outcome must be replanned", ErrUnavailable)
		}
		report.Records[i] = result
	}
	return report, nil
}
