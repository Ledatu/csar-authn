package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/identityimport"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
)

func (s *Store) ReadIdentityImportState(ctx context.Context, record identityimport.Record, override uuid.UUID) (identityimport.State, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return identityimport.State{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return identityImportStateTx(ctx, tx, record, override)
}

func identityImportStateTx(ctx context.Context, tx pgx.Tx, record identityimport.Record, override uuid.UUID) (identityimport.State, error) {
	state := identityimport.State{Matches: map[identityimport.Identity]uuid.UUID{}, ExistingProviders: map[string]string{}}
	for _, link := range record.Identities {
		var id uuid.UUID
		var merged *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT a.user_id,u.merged_into FROM oauth_accounts a JOIN users u ON u.id=a.user_id WHERE a.provider=$1 AND a.provider_user_id=$2`, link.Provider, link.ID).Scan(&id, &merged)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return state, err
		}
		if merged != nil {
			state.InvalidOwnership = true
		}
		state.Matches[link.Identity] = id
		state.Target = id
	}
	for _, id := range record.Conflicts {
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_accounts WHERE provider=$1 AND provider_user_id=$2)`, id.Provider, id.ID).Scan(&found); err != nil {
			return state, err
		}
		state.ForbiddenMatch = state.ForbiddenMatch || found
	}
	if override != uuid.Nil {
		state.Target = override
	}
	if state.Target != uuid.Nil {
		var merged *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT merged_into FROM users WHERE id=$1`, state.Target).Scan(&merged)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return state, err
		}
		state.TargetExists = err == nil && merged == nil
		if err == nil && merged != nil {
			state.InvalidOwnership = true
		}
		rows, err := tx.Query(ctx, `SELECT provider,provider_user_id FROM oauth_accounts WHERE user_id=$1`, state.Target)
		if err != nil {
			return state, err
		}
		for rows.Next() {
			var provider, id string
			if err := rows.Scan(&provider, &id); err != nil {
				rows.Close()
				return state, err
			}
			state.ExistingProviders[provider] = id
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return state, err
		}
	}
	if record.Email != "" {
		email, err := store.NormalizeEmailString(record.Email)
		if err != nil {
			state.ContactConflict = true
		} else {
			var occupied bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email)=lower($1) AND id<>$2 UNION ALL SELECT 1 FROM oauth_accounts WHERE provider='email' AND lower(provider_user_id)=lower($1) AND user_id<>$2)`, email, state.Target).Scan(&occupied); err != nil {
				return state, err
			}
			state.ContactConflict = state.ContactConflict || occupied
		}
	}
	if record.Phone != "" {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, record.Phone)
		if len(digits) < 10 || len(digits) > 15 {
			state.ContactConflict = true
		} else {
			var occupied bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE phone=ANY($1::text[]) AND id<>$2)`, []string{digits, "+" + digits}, state.Target).Scan(&occupied); err != nil {
				return state, err
			}
			state.ContactConflict = state.ContactConflict || occupied
		}
	}
	return state, nil
}

// ApplyIdentityImport replans under short table write locks. These serialize
// concurrent login/contact/link/merge writes as well as other imports, including
// absence checks. This is bounded migration work, not a new ownership lease.
func (s *Store) ApplyIdentityImport(ctx context.Context, m identityimport.Mutation) (identityimport.Plan, error) {
	if s.outbox == nil {
		return identityimport.Plan{}, identityimport.ErrUnavailable
	}
	actor, _ := gatewayctx.FromContext(ctx)
	if actor.Subject != m.Actor || !strings.HasPrefix(m.Actor, "svc:") {
		return identityimport.Plan{}, identityimport.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return identityimport.Plan{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
		return identityimport.Plan{}, err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE users,oauth_accounts IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return identityimport.Plan{}, err
	}
	state, err := identityImportStateTx(ctx, tx, m.Record, m.Override)
	if err != nil {
		return identityimport.Plan{}, err
	}
	plan := identityimport.Decide(m.Record, m.Override, state)
	if plan.Action != "create" && plan.Action != "link" {
		plan.Applied = "skipped"
		return plan, nil
	}
	if plan.Action != m.Expected.Action || plan.UserID != m.Expected.UserID {
		plan.Action = "blocked"
		plan.Reason = "state_changed"
		return plan, nil
	}
	accounts := make([]store.OAuthAccount, 0, len(plan.AddProviders))
	for _, link := range m.Record.Identities {
		if _, exists := state.Matches[link.Identity]; exists {
			continue
		}
		metadata := map[string]interface{}{"linked_by": "identity_import", "import_source": m.Source}
		for key, value := range link.Metadata {
			metadata[key] = value
		}
		accounts = append(accounts, store.OAuthAccount{Provider: link.Provider, ProviderUserID: link.ID, ProviderMetadata: metadata})
	}
	switch plan.Action {
	case "create":
		user, err := s.createUserWithLinksTx(ctx, tx, &store.User{DisplayName: m.Record.DisplayName}, accounts)
		if err != nil {
			return plan, err
		}
		plan.UserID = user.ID
	case "link":
		for i := range accounts {
			if err := s.insertOAuthAccountTx(ctx, tx, &accounts[i], plan.UserID); err != nil {
				return plan, err
			}
		}
	}
	// Audit carries safe source correlation and provider names, no contact, tokens,
	// provider-user IDs or user display metadata.
	stateJSON, err := json.Marshal(map[string]any{"importer": m.Importer, "source": m.Source, "record_key": m.Record.Key, "providers": plan.AddProviders})
	if err != nil {
		return plan, err
	}
	if err := s.enqueueAudit(ctx, tx, &audit.Event{Actor: m.Actor, Action: "identity.import." + plan.Action, TargetType: "user", TargetID: plan.UserID.String(), ScopeType: "platform", AfterState: stateJSON, RequestID: actor.RequestID}); err != nil {
		return plan, err
	}
	if err := tx.Commit(ctx); err != nil {
		return plan, err
	}
	plan.Applied = "ok"
	return plan, nil
}
