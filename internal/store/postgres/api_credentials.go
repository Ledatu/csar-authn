package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ledatu/csar-authn/internal/store"
)

var _ store.APICredentialStore = (*Store)(nil)

func (s *Store) CreateAPICredential(ctx context.Context, key *store.APICredential, maxActive int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin API credential creation: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after a successful commit is harmless

	// Serialize issuance per owner to enforce the active-key cap across replicas.
	var owner uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, key.OwnerID).Scan(&owner); err != nil {
		return fmt.Errorf("lock API credential owner: %w", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM seller_api_credentials
WHERE owner_user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, key.OwnerID).Scan(&count); err != nil {
		return fmt.Errorf("count active API credentials: %w", err)
	}
	if count >= maxActive {
		return store.ErrAPICredentialLimit
	}
	if err := tx.QueryRow(ctx, `INSERT INTO seller_api_credentials
(id, owner_user_id, seller_id, label, token_hash, token_prefix, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at`,
		key.ID, key.OwnerID, key.SellerID, key.Label, key.TokenHash, key.Prefix, key.ExpiresAt,
	).Scan(&key.CreatedAt); err != nil {
		return fmt.Errorf("insert API credential: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit API credential: %w", err)
	}
	return nil
}

func (s *Store) ListAPICredentials(ctx context.Context, ownerID uuid.UUID) ([]store.APICredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, owner_user_id, seller_id, label,
token_prefix, created_at, expires_at, last_used_at, revoked_at
FROM seller_api_credentials WHERE owner_user_id = $1
ORDER BY created_at DESC LIMIT 100`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list API credentials: %w", err)
	}
	defer rows.Close()
	items := make([]store.APICredential, 0)
	for rows.Next() {
		var item store.APICredential
		if err := rows.Scan(&item.ID, &item.OwnerID, &item.SellerID, &item.Label,
			&item.Prefix, &item.CreatedAt, &item.ExpiresAt, &item.LastUsedAt, &item.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan API credential: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeAPICredential(ctx context.Context, ownerID, keyID uuid.UUID) (*store.APICredential, error) {
	var key store.APICredential
	err := s.pool.QueryRow(ctx, `UPDATE seller_api_credentials SET revoked_at = now()
WHERE id = $1 AND owner_user_id = $2 AND revoked_at IS NULL
RETURNING id, seller_id`, keyID, ownerID).Scan(&key.ID, &key.SellerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("revoke API credential: %w", err)
	}
	return &key, nil
}

func (s *Store) FindAPICredentialByHash(ctx context.Context, hash string) (*store.APICredential, error) {
	var item store.APICredential
	err := s.pool.QueryRow(ctx, `SELECT id, owner_user_id, seller_id, label,
token_prefix, created_at, expires_at, last_used_at, revoked_at
FROM seller_api_credentials WHERE token_hash = $1 AND revoked_at IS NULL
AND expires_at > now()`, hash).Scan(&item.ID, &item.OwnerID, &item.SellerID,
		&item.Label, &item.Prefix, &item.CreatedAt, &item.ExpiresAt,
		&item.LastUsedAt, &item.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find API credential: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE seller_api_credentials SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 hour')`, item.ID)
	if err != nil {
		return nil, fmt.Errorf("touch API credential: %w", err)
	}
	return &item, nil
}
