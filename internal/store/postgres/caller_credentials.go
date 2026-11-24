package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

var _ store.CallerCredentialStore = (*Store)(nil)

func (s *Store) CallerForCredential(ctx context.Context, owner uuid.UUID, kind caller.CredentialKind, reference string) (*store.Caller, error) {
	var c store.Caller
	err := s.pool.QueryRow(ctx, `SELECT c.id,c.owner_user_id,c.caller_kind,c.label,c.created_at,c.revoked_at
FROM registered_caller_credentials b JOIN registered_callers c ON c.id=b.caller_id
WHERE b.credential_kind=$1 AND b.credential_id=$2`, kind, reference).
		Scan(&c.ID, &c.OwnerID, &c.Kind, &c.Label, &c.CreatedAt, &c.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.OwnerID != owner {
		return nil, store.ErrCallerBinding
	}
	return &c, nil
}

// Bind only inside the issuer's credential transaction. There is no public
// adoption endpoint that could silently reclassify an existing legacy token.
func (s *Store) bindCallerTx(ctx context.Context, tx pgx.Tx, owner, id uuid.UUID, kind caller.CredentialKind, reference string) error {
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	var confirmed uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM registered_callers WHERE id=$1 AND owner_user_id=$2 AND revoked_at IS NULL FOR UPDATE`, id, owner).Scan(&confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO registered_caller_credentials(credential_kind,credential_id,caller_id,owner_user_id) VALUES($1,$2,$3,$4)`, kind, reference, confirmed, owner); err != nil {
		return err
	}
	state, err := json.Marshal(map[string]any{"caller_id": confirmed, "credential_kind": kind})
	if err != nil {
		return err
	}
	identity, _ := gatewayctx.FromContext(ctx)
	actor := identity.Subject
	if actor == "" {
		actor = owner.String()
	}
	return s.enqueueAudit(ctx, tx, &audit.Event{Actor: actor, Action: "credentials.caller.bind", TargetType: "credential", TargetID: reference,
		ScopeType: "subject", ScopeID: owner.String(), AfterState: state, RequestID: identity.RequestID})
}

// Creation and binding share the credential transaction. A failed credential or
// audit enqueue cannot leave an orphan registration or silently become legacy.
func (s *Store) bindCredentialCallerTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID, id *uuid.UUID, newCaller *store.Caller, kind caller.CredentialKind, reference string) (*uuid.UUID, error) {
	if newCaller != nil {
		if id != nil || newCaller.OwnerID != owner {
			return nil, store.ErrCallerBinding
		}
		if err := newCaller.ValidateRegistration(); err != nil {
			return nil, err
		}
		if s.outbox == nil {
			return nil, store.ErrCallerAuditRequired
		}
		if err := s.createCallerTx(ctx, tx, newCaller, store.DefaultCallerLimit); err != nil {
			return nil, err
		}
		id = &newCaller.ID
	}
	if id == nil {
		return nil, nil
	} // Existing direct store callers can still seed legacy credentials.
	if err := s.bindCallerTx(ctx, tx, owner, *id, kind, reference); err != nil {
		return nil, err
	}
	return id, nil
}
