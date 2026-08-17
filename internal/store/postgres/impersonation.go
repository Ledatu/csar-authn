package postgres

import (
	"context"
	"fmt"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) CreateImpersonationGrant(ctx context.Context, grant *store.ImpersonationGrant) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO impersonation_grants (id, token_hash, admin_user_id, target_user_id, reason, redirect_url, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		grant.ID, grant.TokenHash, grant.AdminUserID, grant.TargetUserID, grant.Reason, grant.RedirectURL, grant.CreatedAt, grant.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create impersonation grant: %w", err)
	}
	return nil
}

func (s *Store) ConsumeImpersonationGrant(ctx context.Context, tokenHash string) (*store.ImpersonationGrant, error) {
	grant := &store.ImpersonationGrant{}
	err := s.pool.QueryRow(ctx,
		`UPDATE impersonation_grants
		 SET consumed_at = now()
		 WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING id, token_hash, admin_user_id, target_user_id, reason, redirect_url, created_at, expires_at, consumed_at`,
		tokenHash,
	).Scan(
		&grant.ID, &grant.TokenHash, &grant.AdminUserID, &grant.TargetUserID,
		&grant.Reason, &grant.RedirectURL, &grant.CreatedAt, &grant.ExpiresAt, &grant.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrImpersonationGrantUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("consume impersonation grant: %w", err)
	}
	return grant, nil
}

func (s *Store) DeleteInactiveImpersonationGrants(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM impersonation_grants WHERE expires_at < now() OR consumed_at IS NOT NULL`,
	)
	if err != nil {
		return 0, fmt.Errorf("delete inactive impersonation grants: %w", err)
	}
	return tag.RowsAffected(), nil
}
