package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/pgutil"

	"github.com/ledatu/csar-authn/internal/store"
)

// legacyUsersSyncLockKey serializes legacy users sync apply runs across authn replicas.
const legacyUsersSyncLockKey int64 = 0x6c65676163797573

// TryLegacyUsersSyncLock takes the session advisory lock for one apply run.
// ok is false when another replica holds it.
func (s *Store) TryLegacyUsersSyncLock(ctx context.Context) (release func(), ok bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquiring connection: %w", err)
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, legacyUsersSyncLockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("taking legacy users sync lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, legacyUsersSyncLockKey)
		conn.Release()
	}, true, nil
}

// LinkLegacyAccount adds a provider link to an existing user. A link that
// already exists, to anyone, is ErrProviderAlreadyLinked.
func (s *Store) LinkLegacyAccount(ctx context.Context, acct *store.OAuthAccount) error {
	if err := s.CreateOAuthAccount(ctx, acct); err != nil {
		if pgutil.IsDuplicateKey(err) {
			return store.ErrProviderAlreadyLinked
		}
		return err
	}
	return nil
}

// CreateLegacyUser inserts a user and all its provider links in one
// transaction, so a concurrent login for one of the links wins cleanly.
func (s *Store) CreateLegacyUser(ctx context.Context, u *store.User, accounts []store.OAuthAccount) (*store.User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	created := *u
	created.ID = uuid.New()
	now := time.Now()
	created.CreatedAt, created.UpdatedAt = now, now
	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, display_name, avatar_storage_key, avatar_preview_storage_key, avatar_master_storage_key,
		                    avatar_url, created_at, updated_at)
		 VALUES ($1, $2, '', '', '', $3, $4, $5)`,
		created.ID, created.DisplayName, created.AvatarURL, created.CreatedAt, created.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("creating legacy user: %w", err)
	}
	for i := range accounts {
		if err := s.insertOAuthAccountTx(ctx, tx, &accounts[i], created.ID); err != nil {
			if pgutil.IsDuplicateKey(err) {
				return nil, store.ErrProviderAlreadyLinked
			}
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing legacy user: %w", err)
	}
	return &created, nil
}
