package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/pgutil"
)

var _ store.CallerRegistryStore = (*Store)(nil)

func (s *Store) CreateCaller(ctx context.Context, c *store.Caller, maxActive int) error {
	if err := c.ValidateRegistration(); err != nil {
		return err
	}
	if maxActive < 1 || maxActive > 100 {
		return fmt.Errorf("caller cap must be between 1 and 100")
	}
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.createCallerTx(ctx, tx, c, maxActive)
	})
}

// The caller has already passed registration validation and outbox preflight.
func (s *Store) createCallerTx(ctx context.Context, tx pgx.Tx, c *store.Caller, maxActive int) error {
	var owner uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, c.OwnerID).Scan(&owner); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM registered_callers WHERE owner_user_id=$1 AND revoked_at IS NULL`, c.OwnerID).Scan(&count); err != nil {
		return err
	}
	if count >= maxActive {
		return store.ErrCallerLimit
	}
	if err := tx.QueryRow(ctx, `INSERT INTO registered_callers(id,owner_user_id,caller_kind,label)
VALUES($1,$2,$3,$4) RETURNING created_at`, c.ID, c.OwnerID, c.Kind, c.Label).Scan(&c.CreatedAt); err != nil {
		return err
	}
	return s.enqueueCaller(ctx, tx, "credentials.caller.create", c)
}

func (s *Store) ListActiveCallers(ctx context.Context, owner uuid.UUID) ([]store.Caller, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,owner_user_id,caller_kind,label,created_at FROM registered_callers
WHERE owner_user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 100`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]store.Caller, 0)
	for rows.Next() {
		var c store.Caller
		if err := rows.Scan(&c.ID, &c.OwnerID, &c.Kind, &c.Label, &c.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

func (s *Store) RevokeCaller(ctx context.Context, owner, id uuid.UUID) (*store.Caller, error) {
	if s.outbox == nil {
		return nil, store.ErrCallerAuditRequired
	}
	var c store.Caller
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockCredentialOwnerTx(ctx, tx, owner); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `UPDATE registered_callers SET revoked_at=clock_timestamp()
WHERE id=$1 AND owner_user_id=$2 AND revoked_at IS NULL
RETURNING id,owner_user_id,caller_kind,label,created_at,revoked_at`, id, owner).
			Scan(&c.ID, &c.OwnerID, &c.Kind, &c.Label, &c.CreatedAt, &c.RevokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE seller_api_credentials SET revoked_at=clock_timestamp()
WHERE owner_user_id=$2 AND id::text IN (SELECT credential_id FROM registered_caller_credentials WHERE caller_id=$1 AND credential_kind='api_key') AND revoked_at IS NULL`, id, owner); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM seller_mcp_grants WHERE owner_id=$2 AND id::text IN
(SELECT credential_id FROM registered_caller_credentials WHERE caller_id=$1 AND credential_kind='oauth_access')`, id, owner); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE credential_grants SET revoked_at=clock_timestamp() WHERE owner_user_id=$1 AND caller_id=$2 AND revoked_at IS NULL`, owner, id); err != nil {
			return err
		}
		return s.enqueueCaller(ctx, tx, "credentials.caller.revoke", &c)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) enqueueCaller(ctx context.Context, tx pgx.Tx, action string, c *store.Caller) error {
	state, err := json.Marshal(map[string]any{"caller_id": c.ID, "caller_kind": c.Kind, "owner_subject": c.OwnerID, "revoked": c.RevokedAt != nil})
	if err != nil {
		return err
	}
	id, _ := gatewayctx.FromContext(ctx)
	actor := id.Subject
	if actor == "" {
		actor = c.OwnerID.String()
	}
	return s.enqueueAudit(ctx, tx, &audit.Event{Actor: actor, Action: action, TargetType: "caller", TargetID: c.ID.String(),
		ScopeType: "subject", ScopeID: c.OwnerID.String(), AfterState: state, RequestID: id.RequestID})
}
