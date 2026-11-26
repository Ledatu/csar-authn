package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
)

var _ store.CredentialCapacityReader = (*Store)(nil)

func checkConnectionCapacityTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID) error {
	var confirmed uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, owner).Scan(&confirmed); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, connectionCredentialCountSQL, owner).Scan(&count); err != nil {
		return err
	}
	if count >= store.CredentialOAuthLimit {
		return store.ErrCredentialConnectionLimit
	}
	return nil
}

// Preserve historical grants in the same accounting family. Retirement removes
// protocol entry points, not stored consent, owner caps or revocation cleanup.
const connectionCredentialCountSQL = `SELECT (SELECT count(*) FROM seller_mcp_grants WHERE owner_id=$1 AND expires_at>now()
 AND (coalesce(access_hash,session_access_hash) IS NOT NULL OR code_expires_at>now())) + (SELECT count(*) FROM credential_grants g WHERE owner_user_id=$1 AND credential_kind='oauth_access' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM credential_secrets x WHERE x.grant_id=g.id AND x.purpose IN ('access','refresh','authorization_code') AND x.spent_at IS NULL AND x.expires_at>clock_timestamp()))`

// CredentialCapacity uses the mutation path's exact mixed-family counts.
func (s *Store) CredentialCapacity(ctx context.Context, owner uuid.UUID) (store.CredentialCapacity, error) {
	var out store.CredentialCapacity
	if owner == uuid.Nil {
		return out, store.ErrCredentialInvalid
	}
	if err := s.pool.QueryRow(ctx, apiCredentialCountSQL, owner).Scan(&out.APIKeys); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, connectionCredentialCountSQL, owner).Scan(&out.Connections); err != nil {
		return out, err
	}
	return out, nil
}
