package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

const serviceAccountColumns = `name, public_key_pem, allowed_audiences, allow_all_audiences,
 token_ttl, status, created_at, rotated_at, revoked_at, reactivated_at, revision, generation`

type serviceAccountScanner interface {
	Scan(dest ...any) error
}

func scanServiceAccount(row serviceAccountScanner) (*store.ServiceAccount, error) {
	var sa store.ServiceAccount
	var ttl time.Duration
	if err := row.Scan(&sa.Name, &sa.PublicKeyPEM, &sa.AllowedAudiences,
		&sa.AllowAllAudiences, &ttl, &sa.Status, &sa.CreatedAt, &sa.RotatedAt,
		&sa.RevokedAt, &sa.ReactivatedAt, &sa.Revision, &sa.Generation); err != nil {
		return nil, err
	}
	sa.TokenTTL = ttl
	return &sa, nil
}

func (s *Store) ListActiveServiceAccounts(ctx context.Context) ([]store.ServiceAccount, error) {
	return s.ListServiceAccounts(ctx, "active")
}

func (s *Store) ListServiceAccounts(ctx context.Context, status string) ([]store.ServiceAccount, error) {
	if status != "active" && status != "revoked" && status != "all" {
		return nil, fmt.Errorf("invalid service account status %q", status)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts
         WHERE ($1 = 'all' OR status = $1) ORDER BY name`, status)
	if err != nil {
		return nil, fmt.Errorf("listing service accounts: %w", err)
	}
	defer rows.Close()

	var accounts []store.ServiceAccount
	for rows.Next() {
		sa, scanErr := scanServiceAccount(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scanning service account: %w", scanErr)
		}
		accounts = append(accounts, *sa)
	}
	return accounts, rows.Err()
}

func (s *Store) GetServiceAccount(ctx context.Context, name string) (*store.ServiceAccount, error) {
	sa, err := scanServiceAccount(s.pool.QueryRow(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE name = $1`, name))
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get service account: %w", err)
	}
	return sa, nil
}

func (s *Store) CreateServiceAccount(ctx context.Context, sa *store.ServiceAccount) error {
	sa.CreatedAt = time.Now()
	if sa.Status == "" {
		sa.Status = "active"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO service_accounts
         (name, public_key_pem, allowed_audiences, allow_all_audiences, token_ttl, status, created_at)
         VALUES ($1, $2, $3, $4, $5::interval, $6, $7)`,
		sa.Name, sa.PublicKeyPEM, sa.AllowedAudiences, sa.AllowAllAudiences,
		intervalValue(sa.TokenTTL), sa.Status, sa.CreatedAt)
	if pgutil.IsDuplicateKey(err) {
		return store.ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create service account: %w", err)
	}
	sa.Revision = 1
	sa.Generation = 1
	return nil
}

func intervalValue(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int(d.Seconds()))
}

func (s *Store) CreateOrReactivateServiceAccount(ctx context.Context, sa *store.ServiceAccount) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin service account creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := scanServiceAccount(tx.QueryRow(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE name = $1 FOR UPDATE`, sa.Name))
	switch {
	case pgutil.IsNotFound(err):
		created, insertErr := scanServiceAccount(tx.QueryRow(ctx,
			`INSERT INTO service_accounts
             (name, public_key_pem, allowed_audiences, allow_all_audiences, token_ttl, status)
             VALUES ($1, $2, $3, $4, $5::interval, 'active')
             RETURNING `+serviceAccountColumns,
			sa.Name, sa.PublicKeyPEM, sa.AllowedAudiences, sa.AllowAllAudiences, intervalValue(sa.TokenTTL)))
		if pgutil.IsDuplicateKey(insertErr) {
			return false, store.ErrAlreadyExists
		}
		if insertErr != nil {
			return false, fmt.Errorf("insert service account: %w", insertErr)
		}
		*sa = *created
	case err != nil:
		return false, fmt.Errorf("lock service account: %w", err)
	case existing.Status == "active":
		return false, store.ErrAlreadyExists
	case store.SamePublicKeyPEM(existing.PublicKeyPEM, sa.PublicKeyPEM):
		return false, store.ErrKeyUnchanged
	default:
		reactivated, updateErr := scanServiceAccount(tx.QueryRow(ctx,
			`UPDATE service_accounts SET public_key_pem = $2,
             allowed_audiences = $3, allow_all_audiences = $4,
             token_ttl = $5::interval, status = 'active', revoked_at = NULL,
             reactivated_at = now(), revision = revision + 1,
             generation = generation + 1
             WHERE name = $1 AND status = 'revoked'
             RETURNING `+serviceAccountColumns,
			sa.Name, sa.PublicKeyPEM, sa.AllowedAudiences, sa.AllowAllAudiences, intervalValue(sa.TokenTTL)))
		if updateErr != nil {
			return false, fmt.Errorf("reactivate service account: %w", updateErr)
		}
		*sa = *reactivated
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit service account creation: %w", err)
	}
	return existing != nil, nil
}

func (s *Store) UpdateServiceAccountPolicy(ctx context.Context, name string, audiences []string, allowAll bool, ttl time.Duration, revision int64) (*store.ServiceAccount, error) {
	sa, err := scanServiceAccount(s.pool.QueryRow(ctx,
		`UPDATE service_accounts SET allowed_audiences = $2,
         allow_all_audiences = $3, token_ttl = $4::interval,
         revision = revision + 1
         WHERE name = $1 AND status = 'active' AND revision = $5
         RETURNING `+serviceAccountColumns,
		name, audiences, allowAll, intervalValue(ttl), revision))
	if err == nil {
		return sa, nil
	}
	if !pgutil.IsNotFound(err) {
		return nil, fmt.Errorf("update service account policy: %w", err)
	}
	current, getErr := s.GetServiceAccount(ctx, name)
	if getErr != nil {
		return nil, getErr
	}
	if current.Status != "active" {
		return nil, store.ErrInactive
	}
	return nil, store.ErrRevisionMismatch
}

func (s *Store) UpdateServiceAccountKey(ctx context.Context, name, newPEM string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE service_accounts SET public_key_pem = $2, rotated_at = now(),
         revision = revision + 1 WHERE name = $1 AND status = 'active'`, name, newPEM)
	if err != nil {
		return fmt.Errorf("update service account key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeServiceAccount(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE service_accounts SET status = 'revoked', revoked_at = now(),
         revision = revision + 1 WHERE name = $1 AND status = 'active'`, name)
	if err != nil {
		return fmt.Errorf("revoke service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}
