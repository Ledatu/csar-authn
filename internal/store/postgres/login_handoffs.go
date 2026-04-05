package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) CreateLoginHandoff(ctx context.Context, handoff *store.LoginHandoff) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO login_handoffs
		 (id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		  desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		handoff.ID, handoff.ScanTokenHash, handoff.DesktopSecretHash, handoff.RedirectURL, handoff.Status,
		handoff.ApprovedByUserID, handoff.DesktopUserAgent, handoff.DesktopIPAddress, handoff.CreatedAt,
		handoff.ExpiresAt, handoff.ApprovedAt, handoff.DeniedAt, handoff.ConsumedAt,
	)
	if err != nil {
		return fmt.Errorf("create login handoff: %w", err)
	}
	return nil
}

func (s *Store) GetLoginHandoffByScanToken(ctx context.Context, scanTokenHash string) (*store.LoginHandoff, error) {
	handoff := &store.LoginHandoff{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		        desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at
		 FROM login_handoffs
		 WHERE scan_token_hash = $1`,
		scanTokenHash,
	).Scan(
		&handoff.ID, &handoff.ScanTokenHash, &handoff.DesktopSecretHash, &handoff.RedirectURL, &handoff.Status,
		&handoff.ApprovedByUserID, &handoff.DesktopUserAgent, &handoff.DesktopIPAddress, &handoff.CreatedAt,
		&handoff.ExpiresAt, &handoff.ApprovedAt, &handoff.DeniedAt, &handoff.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get login handoff by scan token: %w", err)
	}
	return handoff, nil
}

func (s *Store) GetLoginHandoffStatusForDesktop(ctx context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	handoff := &store.LoginHandoff{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		        desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at
		 FROM login_handoffs
		 WHERE id = $1`,
		id,
	).Scan(
		&handoff.ID, &handoff.ScanTokenHash, &handoff.DesktopSecretHash, &handoff.RedirectURL, &handoff.Status,
		&handoff.ApprovedByUserID, &handoff.DesktopUserAgent, &handoff.DesktopIPAddress, &handoff.CreatedAt,
		&handoff.ExpiresAt, &handoff.ApprovedAt, &handoff.DeniedAt, &handoff.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get login handoff for desktop: %w", err)
	}
	return handoff, nil
}

func (s *Store) ApproveLoginHandoff(ctx context.Context, id uuid.UUID, approvedByUserID uuid.UUID) (*store.LoginHandoff, error) {
	handoff := &store.LoginHandoff{}
	err := s.pool.QueryRow(ctx,
		`UPDATE login_handoffs
		 SET status = 'approved',
		     approved_by_user_id = $2,
		     approved_at = now()
		 WHERE id = $1
		   AND status = 'pending'
		   AND expires_at > now()
		 RETURNING id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		           desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at`,
		id, approvedByUserID,
	).Scan(
		&handoff.ID, &handoff.ScanTokenHash, &handoff.DesktopSecretHash, &handoff.RedirectURL, &handoff.Status,
		&handoff.ApprovedByUserID, &handoff.DesktopUserAgent, &handoff.DesktopIPAddress, &handoff.CreatedAt,
		&handoff.ExpiresAt, &handoff.ApprovedAt, &handoff.DeniedAt, &handoff.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("approve login handoff: %w", err)
	}
	return handoff, nil
}

func (s *Store) DenyLoginHandoff(ctx context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	handoff := &store.LoginHandoff{}
	err := s.pool.QueryRow(ctx,
		`UPDATE login_handoffs
		 SET status = 'denied',
		     denied_at = now()
		 WHERE id = $1
		   AND status = 'pending'
		   AND expires_at > now()
		 RETURNING id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		           desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at`,
		id,
	).Scan(
		&handoff.ID, &handoff.ScanTokenHash, &handoff.DesktopSecretHash, &handoff.RedirectURL, &handoff.Status,
		&handoff.ApprovedByUserID, &handoff.DesktopUserAgent, &handoff.DesktopIPAddress, &handoff.CreatedAt,
		&handoff.ExpiresAt, &handoff.ApprovedAt, &handoff.DeniedAt, &handoff.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("deny login handoff: %w", err)
	}
	return handoff, nil
}

func (s *Store) ConsumeApprovedLoginHandoff(ctx context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	handoff := &store.LoginHandoff{}
	err := s.pool.QueryRow(ctx,
		`UPDATE login_handoffs
		 SET status = 'consumed',
		     consumed_at = now()
		 WHERE id = $1
		   AND status = 'approved'
		   AND expires_at > now()
		 RETURNING id, scan_token_hash, desktop_secret_hash, redirect_url, status, approved_by_user_id,
		           desktop_user_agent, desktop_ip_address, created_at, expires_at, approved_at, denied_at, consumed_at`,
		id,
	).Scan(
		&handoff.ID, &handoff.ScanTokenHash, &handoff.DesktopSecretHash, &handoff.RedirectURL, &handoff.Status,
		&handoff.ApprovedByUserID, &handoff.DesktopUserAgent, &handoff.DesktopIPAddress, &handoff.CreatedAt,
		&handoff.ExpiresAt, &handoff.ApprovedAt, &handoff.DeniedAt, &handoff.ConsumedAt,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("consume login handoff: %w", err)
	}
	return handoff, nil
}

func (s *Store) ExpireLoginHandoff(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE login_handoffs
		 SET status = 'expired'
		 WHERE id = $1
		   AND status = 'pending'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("expire login handoff: %w", err)
	}
	return nil
}

func (s *Store) CountPendingLoginHandoffs(ctx context.Context, ipAddress string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM login_handoffs
		 WHERE desktop_ip_address = $1
		   AND status = 'pending'
		   AND expires_at > now()`,
		ipAddress,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending login handoffs: %w", err)
	}
	return count, nil
}

func (s *Store) DeleteInactiveLoginHandoffs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM login_handoffs
		 WHERE status IN ('denied', 'consumed', 'expired')
		    OR expires_at <= now()`,
	)
	if err != nil {
		return 0, fmt.Errorf("delete inactive login handoffs: %w", err)
	}
	return tag.RowsAffected(), nil
}
