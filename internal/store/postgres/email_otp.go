package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ledatu/csar-core/pgutil"

	"github.com/ledatu/csar-authn/internal/store"
)

func (s *Store) CreateEmailOTPChallenge(ctx context.Context, challenge *store.EmailOTPChallenge) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO email_otp_challenges
		 (id, email, code_hash, intent, user_id, status, attempts, created_at, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		challenge.ID,
		challenge.Email,
		challenge.CodeHash,
		challenge.Intent,
		challenge.UserID,
		challenge.Status,
		challenge.Attempts,
		challenge.CreatedAt,
		challenge.ExpiresAt,
		challenge.UserAgent,
		challenge.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("creating email OTP challenge: %w", err)
	}
	return nil
}

func (s *Store) VerifyEmailOTPChallenge(ctx context.Context, id uuid.UUID, codeHash string, maxAttempts int) (*store.EmailOTPChallenge, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin email OTP verify tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	challenge := &store.EmailOTPChallenge{}
	err = tx.QueryRow(ctx,
		`SELECT id, email, code_hash, intent, user_id, status, attempts,
		        created_at, expires_at, consumed_at, user_agent, ip_address
		   FROM email_otp_challenges
		  WHERE id = $1
		  FOR UPDATE`,
		id,
	).Scan(
		&challenge.ID,
		&challenge.Email,
		&challenge.CodeHash,
		&challenge.Intent,
		&challenge.UserID,
		&challenge.Status,
		&challenge.Attempts,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.ConsumedAt,
		&challenge.UserAgent,
		&challenge.IPAddress,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrEmailOTPUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("get email OTP challenge: %w", err)
	}
	if challenge.Status != "pending" || !time.Now().Before(challenge.ExpiresAt) {
		if challenge.Status == "pending" {
			if _, updateErr := tx.Exec(ctx, `UPDATE email_otp_challenges SET status = 'expired' WHERE id = $1`, id); updateErr != nil {
				return nil, fmt.Errorf("expiring email OTP challenge: %w", updateErr)
			}
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return nil, fmt.Errorf("commit expired email OTP challenge: %w", commitErr)
			}
		}
		return nil, store.ErrEmailOTPUnavailable
	}
	if challenge.Attempts >= maxAttempts {
		return nil, store.ErrEmailOTPTooManyAttempts
	}
	if challenge.CodeHash != codeHash {
		newAttempts := challenge.Attempts + 1
		status := "pending"
		errResult := store.ErrEmailOTPInvalidCode
		if newAttempts >= maxAttempts {
			status = "expired"
			errResult = store.ErrEmailOTPTooManyAttempts
		}
		if _, updateErr := tx.Exec(ctx,
			`UPDATE email_otp_challenges
			    SET attempts = $2, status = $3
			  WHERE id = $1`,
			id,
			newAttempts,
			status,
		); updateErr != nil {
			return nil, fmt.Errorf("updating email OTP attempts: %w", updateErr)
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return nil, fmt.Errorf("commit email OTP attempts: %w", commitErr)
		}
		return nil, errResult
	}

	err = tx.QueryRow(ctx,
		`UPDATE email_otp_challenges
		    SET status = 'consumed',
		        attempts = attempts + 1,
		        consumed_at = now()
		  WHERE id = $1
		  RETURNING id, email, code_hash, intent, user_id, status, attempts,
		            created_at, expires_at, consumed_at, user_agent, ip_address`,
		id,
	).Scan(
		&challenge.ID,
		&challenge.Email,
		&challenge.CodeHash,
		&challenge.Intent,
		&challenge.UserID,
		&challenge.Status,
		&challenge.Attempts,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.ConsumedAt,
		&challenge.UserAgent,
		&challenge.IPAddress,
	)
	if err != nil {
		return nil, fmt.Errorf("consuming email OTP challenge: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit email OTP verify tx: %w", err)
	}
	return challenge, nil
}

func (s *Store) CountPendingEmailOTPChallengesByIP(ctx context.Context, ipAddress string) (int, error) {
	return s.countPendingEmailOTPChallenges(ctx, "ip_address", ipAddress)
}

func (s *Store) CountPendingEmailOTPChallengesByEmail(ctx context.Context, email string) (int, error) {
	return s.countPendingEmailOTPChallenges(ctx, "email", email)
}

func (s *Store) countPendingEmailOTPChallenges(ctx context.Context, column, value string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM email_otp_challenges WHERE %s = $1 AND status = 'pending' AND expires_at > now()`, column),
		value,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting pending email OTP challenges by %s: %w", column, err)
	}
	return count, nil
}

func (s *Store) GetLatestEmailOTPChallengeByEmail(ctx context.Context, email string) (*store.EmailOTPChallenge, error) {
	challenge := &store.EmailOTPChallenge{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, code_hash, intent, user_id, status, attempts,
		        created_at, expires_at, consumed_at, user_agent, ip_address
		   FROM email_otp_challenges
		  WHERE email = $1
		  ORDER BY created_at DESC
		  LIMIT 1`,
		email,
	).Scan(
		&challenge.ID,
		&challenge.Email,
		&challenge.CodeHash,
		&challenge.Intent,
		&challenge.UserID,
		&challenge.Status,
		&challenge.Attempts,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.ConsumedAt,
		&challenge.UserAgent,
		&challenge.IPAddress,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get latest email OTP challenge: %w", err)
	}
	return challenge, nil
}

func (s *Store) CleanExpiredEmailOTPChallenges(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE email_otp_challenges
		    SET status = 'expired'
		  WHERE status = 'pending'
		    AND expires_at <= now()`,
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired email OTP challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}
