package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) CreatePasskey(ctx context.Context, passkey *store.Passkey) error {
	if passkey.ID == uuid.Nil {
		passkey.ID = uuid.New()
	}
	normalizePasskeyForStorage(passkey)
	now := time.Now().UTC()
	passkey.CreatedAt = now
	passkey.UpdatedAt = now

	_, err := s.pool.Exec(ctx,
		`INSERT INTO passkeys (
			id, user_id, label, credential_id, public_key, attestation_type, transports,
			user_present, user_verified, backup_eligible, backup_state, aaguid, sign_count,
			attachment, attestation_client_data_json, attestation_client_data_hash,
			attestation_authenticator_data, attestation_object, attestation_public_key_algorithm,
			created_at, last_used_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18, $19,
			$20, $21, $22
		)`,
		passkey.ID, passkey.UserID, passkey.Label, passkey.CredentialID, passkey.PublicKey, passkey.AttestationType, passkey.Transports,
		passkey.UserPresent, passkey.UserVerified, passkey.BackupEligible, passkey.BackupState, passkey.AAGUID, int64(passkey.SignCount),
		passkey.Attachment, passkey.AttestationClientDataJSON, passkey.AttestationClientDataHash, passkey.AttestationAuthenticatorData,
		passkey.AttestationObject, passkey.AttestationPublicKeyAlgorithm, passkey.CreatedAt, passkey.LastUsedAt, passkey.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "passkeys_credential_id_key") {
			return store.ErrPasskeyAlreadyLinked
		}
		return fmt.Errorf("create passkey: %w", err)
	}
	return nil
}

func normalizePasskeyForStorage(passkey *store.Passkey) {
	passkey.CredentialID = nonNilBytes(passkey.CredentialID)
	passkey.PublicKey = nonNilBytes(passkey.PublicKey)
	passkey.Transports = nonNilStrings(passkey.Transports)
	passkey.AAGUID = nonNilBytes(passkey.AAGUID)
	passkey.AttestationClientDataJSON = nonNilBytes(passkey.AttestationClientDataJSON)
	passkey.AttestationClientDataHash = nonNilBytes(passkey.AttestationClientDataHash)
	passkey.AttestationAuthenticatorData = nonNilBytes(passkey.AttestationAuthenticatorData)
	passkey.AttestationObject = nonNilBytes(passkey.AttestationObject)
}

func nonNilBytes(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func nonNilStrings(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

func (s *Store) ListPasskeysByUserID(ctx context.Context, userID uuid.UUID) ([]store.Passkey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, label, credential_id, public_key, attestation_type, transports,
		        user_present, user_verified, backup_eligible, backup_state, aaguid, sign_count,
		        attachment, attestation_client_data_json, attestation_client_data_hash,
		        attestation_authenticator_data, attestation_object, attestation_public_key_algorithm,
		        created_at, last_used_at, updated_at
		   FROM passkeys
		  WHERE user_id = $1
		  ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()

	var passkeys []store.Passkey
	for rows.Next() {
		passkey, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		passkeys = append(passkeys, *passkey)
	}
	return passkeys, rows.Err()
}

func (s *Store) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*store.Passkey, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, label, credential_id, public_key, attestation_type, transports,
		        user_present, user_verified, backup_eligible, backup_state, aaguid, sign_count,
		        attachment, attestation_client_data_json, attestation_client_data_hash,
		        attestation_authenticator_data, attestation_object, attestation_public_key_algorithm,
		        created_at, last_used_at, updated_at
		   FROM passkeys
		  WHERE credential_id = $1`,
		credentialID,
	)
	passkey, err := scanPasskey(row)
	if err != nil {
		if pgutil.IsNotFound(err) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("get passkey by credential id: %w", err)
	}
	return passkey, nil
}

func (s *Store) DeletePasskey(ctx context.Context, passkeyID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete passkey tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&locked); err != nil {
		if pgutil.IsNotFound(err) {
			return store.ErrNotFound
		}
		return fmt.Errorf("lock user for passkey delete: %w", err)
	}

	var loginMethodCount int
	if err := tx.QueryRow(ctx,
		`SELECT
		   (SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1) +
		   (SELECT COUNT(*) FROM passkeys WHERE user_id = $1)`,
		userID,
	).Scan(&loginMethodCount); err != nil {
		return fmt.Errorf("count login methods before passkey delete: %w", err)
	}
	if loginMethodCount <= 1 {
		return store.ErrLastLoginMethod
	}

	tag, err := tx.Exec(ctx,
		`DELETE FROM passkeys WHERE id = $1 AND user_id = $2`,
		passkeyID, userID,
	)
	if err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete passkey: %w", err)
	}
	return nil
}

func (s *Store) UpdatePasskeyUsage(ctx context.Context, passkeyID uuid.UUID, signCount uint32, backupState bool, userVerified bool, lastUsedAt time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE passkeys
		    SET sign_count = $2,
		        backup_state = $3,
		        user_verified = $4,
		        last_used_at = $5,
		        updated_at = now()
		  WHERE id = $1`,
		passkeyID, int64(signCount), backupState, userVerified, lastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("update passkey usage: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) CountUserLoginMethods(ctx context.Context, userID uuid.UUID) (int, error) {
	var oauthCount, passkeyCount int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1`, userID).Scan(&oauthCount); err != nil {
		return 0, fmt.Errorf("count oauth login methods: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM passkeys WHERE user_id = $1`, userID).Scan(&passkeyCount); err != nil {
		return 0, fmt.Errorf("count passkey login methods: %w", err)
	}
	return oauthCount + passkeyCount, nil
}

func (s *Store) CreatePasskeyChallenge(ctx context.Context, challenge *store.PasskeyChallenge) error {
	if challenge.ID == uuid.Nil {
		challenge.ID = uuid.New()
	}
	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = time.Now().UTC()
	}
	var userID any
	if challenge.UserID != nil {
		userID = *challenge.UserID
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO passkey_challenges (id, user_id, kind, session_data, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		challenge.ID, userID, challenge.Kind, json.RawMessage(challenge.SessionData), challenge.CreatedAt, challenge.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create passkey challenge: %w", err)
	}
	return nil
}

func (s *Store) ConsumePasskeyChallenge(ctx context.Context, id uuid.UUID, kind string) (*store.PasskeyChallenge, error) {
	challenge := &store.PasskeyChallenge{}
	err := s.pool.QueryRow(ctx,
		`UPDATE passkey_challenges
		    SET consumed_at = now()
		  WHERE id = $1
		    AND kind = $2
		    AND consumed_at IS NULL
		    AND expires_at > now()
		RETURNING id, user_id, kind, session_data, created_at, expires_at, consumed_at`,
		id, kind,
	).Scan(&challenge.ID, &challenge.UserID, &challenge.Kind, &challenge.SessionData, &challenge.CreatedAt, &challenge.ExpiresAt, &challenge.ConsumedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume passkey challenge: %w", err)
	}
	return challenge, nil
}

func (s *Store) CleanExpiredPasskeyChallenges(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM passkey_challenges WHERE expires_at <= now() OR consumed_at IS NOT NULL`,
	)
	if err != nil {
		return 0, fmt.Errorf("clean passkey challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}

type passkeyScanner interface {
	Scan(dest ...any) error
}

func scanPasskey(scanner passkeyScanner) (*store.Passkey, error) {
	passkey := &store.Passkey{}
	var signCount int64
	if err := scanner.Scan(
		&passkey.ID, &passkey.UserID, &passkey.Label, &passkey.CredentialID, &passkey.PublicKey, &passkey.AttestationType, &passkey.Transports,
		&passkey.UserPresent, &passkey.UserVerified, &passkey.BackupEligible, &passkey.BackupState, &passkey.AAGUID, &signCount,
		&passkey.Attachment, &passkey.AttestationClientDataJSON, &passkey.AttestationClientDataHash, &passkey.AttestationAuthenticatorData,
		&passkey.AttestationObject, &passkey.AttestationPublicKeyAlgorithm, &passkey.CreatedAt, &passkey.LastUsedAt, &passkey.UpdatedAt,
	); err != nil {
		return nil, err
	}
	passkey.SignCount = uint32(signCount)
	return passkey, nil
}
