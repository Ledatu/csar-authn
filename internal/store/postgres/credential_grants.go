package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/pgutil"
)

var _ store.GenericCredentialStore = (*Store)(nil)

func (s *Store) CreateCredentialGrant(ctx context.Context, g *store.CredentialGrant, secrets []store.CredentialSecret, fresh *store.Caller) error {
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	if g == nil {
		return store.ErrCredentialInvalid
	}
	copyGrant := *g
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error { return s.createCredentialGrantTx(ctx, tx, &copyGrant, secrets, fresh) })
	if err == nil {
		*g = copyGrant
	}
	return err
}

func lockCredentialOwnerTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID) error {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 AND merged_into IS NULL FOR UPDATE`, owner).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func lockCredentialCallerTx(ctx context.Context, tx pgx.Tx, owner, id uuid.UUID) error {
	var confirmed uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM registered_callers WHERE owner_user_id=$1 AND id=$2 AND revoked_at IS NULL FOR UPDATE`, owner, id).Scan(&confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func (s *Store) createCredentialGrantTx(ctx context.Context, tx pgx.Tx, g *store.CredentialGrant, secrets []store.CredentialSecret, fresh *store.Caller) error {
	if g == nil || g.RevokedAt != nil || g.LastUsedAt != nil {
		return store.ErrCredentialInvalid
	}
	if err := lockCredentialOwnerTx(ctx, tx, g.OwnerID); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&g.CreatedAt); err != nil {
		return err
	}
	g.ExpiresAt = g.ExpiresAt.UTC().Truncate(time.Microsecond)
	if g.Validate() != nil || !g.ExpiresAt.After(g.CreatedAt) {
		return store.ErrCredentialInvalid
	}
	// The same owner lock/cap includes both the old and new physical families.
	switch g.Kind {
	case caller.APIKey:
		if err := checkAPICapacityTx(ctx, tx, g.OwnerID, store.CredentialAPIKeyLimit); err != nil {
			return err
		}
	case caller.OAuthAccess:
		if err := s.checkMCPCapacityTx(ctx, tx, g.OwnerID); err != nil {
			return err
		}
	default:
		return store.ErrCredentialInvalid
	}
	if fresh != nil {
		copyCaller := *fresh
		if copyCaller.OwnerID != g.OwnerID || copyCaller.ID != g.CallerID {
			return store.ErrCallerBinding
		}
		if err := copyCaller.ValidateRegistration(); err != nil {
			return err
		}
		if err := s.createCallerTx(ctx, tx, &copyCaller, store.DefaultCallerLimit); err != nil {
			return err
		}
	}
	if err := lockCredentialCallerTx(ctx, tx, g.OwnerID, g.CallerID); err != nil {
		return err
	}
	if len(secrets) != 1 || secrets[0].ParentID != nil || (secrets[0].Purpose != store.SecretAccess && secrets[0].Purpose != store.SecretCode) || secrets[0].Purpose == store.SecretAccess && g.ClientBinding != nil || secrets[0].Purpose == store.SecretCode && g.ClientBinding == nil {
		return store.ErrCredentialInvalid
	}
	constraints, err := json.Marshal(g.Constraints)
	if err != nil || len(constraints) > store.MaxCredentialJSONBytes {
		return store.ErrCredentialInvalid
	}
	var binding []byte
	if g.ClientBinding != nil {
		binding, err = json.Marshal(g.ClientBinding)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_grants(id,schema_version,owner_user_id,caller_id,credential_kind,constraints,client_binding,label,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, g.ID, g.SchemaVersion, g.OwnerID, g.CallerID, g.Kind, constraints, binding, g.Label, g.CreatedAt, g.ExpiresAt); err != nil {
		return err
	}
	for _, secret := range secrets {
		secret.CreatedAt = g.CreatedAt
		if err := insertCredentialSecretTx(ctx, tx, g, secret); err != nil {
			return err
		}
	}
	return s.enqueueCredential(ctx, tx, "credentials.grant.create", g, g.ID)
}

func checkAPICapacityTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID, limit int) error {
	var count int
	if limit < 1 || limit > store.CredentialAPIKeyLimit {
		return store.ErrCredentialInvalid
	}
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM seller_api_credentials WHERE owner_user_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp())+(SELECT count(*) FROM credential_grants WHERE owner_user_id=$1 AND credential_kind='api_key' AND revoked_at IS NULL AND expires_at>clock_timestamp())`, owner).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return store.ErrAPICredentialLimit
	}
	return nil
}

func (s *Store) RevokeCredentialGrant(ctx context.Context, owner, id uuid.UUID) error {
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockCredentialOwnerTx(ctx, tx, owner); err != nil {
			return err
		}
		var g store.CredentialGrant
		g.ID, g.OwnerID = id, owner
		err := tx.QueryRow(ctx, `UPDATE credential_grants SET revoked_at=clock_timestamp() WHERE id=$1 AND owner_user_id=$2 AND revoked_at IS NULL RETURNING caller_id`, id, owner).Scan(&g.CallerID)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		return s.enqueueCredential(ctx, tx, "credentials.grant.revoke", &g, id)
	})
}
func (s *Store) enqueueCredential(ctx context.Context, tx pgx.Tx, action string, g *store.CredentialGrant, ref uuid.UUID) error {
	state, err := json.Marshal(map[string]any{"grant_id": g.ID, "caller_id": g.CallerID, "operation_ref": ref})
	if err != nil {
		return err
	}
	return s.enqueueAudit(ctx, tx, &audit.Event{Actor: g.OwnerID.String(), Action: action, TargetType: "credential_grant", TargetID: g.ID.String(), ScopeType: "subject", ScopeID: g.OwnerID.String(), AfterState: state})
}

// Called with the source owner locked by MergeUsers. No consent is transferred.
// No generic state means legacy-only merges retain their existing behavior.
func (s *Store) revokeCredentialOwnerTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM credential_grants WHERE owner_user_id=$1 AND revoked_at IS NULL)`, owner).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_grants SET revoked_at=clock_timestamp() WHERE owner_user_id=$1 AND revoked_at IS NULL`, owner); err != nil {
		return err
	}
	return s.enqueueAudit(ctx, tx, &audit.Event{Actor: owner.String(), Action: "credentials.owner.revoke", TargetType: "credential_owner", TargetID: owner.String(), ScopeType: "subject", ScopeID: owner.String()})
}

// A single query checks the parent, registered caller and live unmerged owner.
// Revocation is never inferred from token shape or mutable deployment profiles.
const credentialStateSQL = `SELECT g.id,g.schema_version,g.owner_user_id,g.caller_id,g.credential_kind,g.constraints,g.client_binding,g.label,g.created_at,g.expires_at,g.revoked_at,g.last_used_at,
 x.id,x.grant_id,x.purpose,x.format_version,x.token_hash,x.created_at,x.expires_at,x.spent_at,x.resource_ref,x.parent_secret_id
 FROM credential_secrets x JOIN credential_grants g ON g.id=x.grant_id
 JOIN registered_callers c ON c.id=g.caller_id AND c.owner_user_id=g.owner_user_id
 JOIN users u ON u.id=g.owner_user_id
 WHERE x.token_hash=$1 AND x.purpose=$2 AND x.format_version=$3
 AND g.revoked_at IS NULL AND c.revoked_at IS NULL AND u.merged_into IS NULL
 AND g.expires_at>clock_timestamp()
 AND (x.expires_at>clock_timestamp() OR (x.purpose='refresh' AND x.spent_at IS NOT NULL))`

func scanCredentialState(row pgx.Row) (store.CredentialState, error) {
	var state store.CredentialState
	g, x := &state.Grant, &state.Secret
	var constraints, binding, resource []byte
	err := row.Scan(&g.ID, &g.SchemaVersion, &g.OwnerID, &g.CallerID, &g.Kind, &constraints, &binding, &g.Label, &g.CreatedAt, &g.ExpiresAt, &g.RevokedAt, &g.LastUsedAt, &x.ID, &x.GrantID, &x.Purpose, &x.FormatVersion, &x.TokenHash, &x.CreatedAt, &x.ExpiresAt, &x.SpentAt, &resource, &x.ParentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, store.ErrNotFound
	}
	if err != nil {
		return state, err
	}
	if store.DecodeCredentialJSON(constraints, &g.Constraints) != nil {
		return state, store.ErrCredentialInvalid
	}
	if binding != nil {
		g.ClientBinding = &store.CredentialClientBinding{}
		if store.DecodeCredentialJSON(binding, g.ClientBinding) != nil {
			return state, store.ErrCredentialInvalid
		}
	}
	if resource != nil {
		if store.DecodeCredentialJSON(resource, &x.Resource) != nil {
			return state, store.ErrCredentialInvalid
		}
	}
	if g.Validate() != nil || x.Validate(g) != nil {
		return state, store.ErrCredentialInvalid
	}
	return state, nil
}
func (s *Store) FindCredentialSecret(ctx context.Context, hash string, purpose store.SecretPurpose, version int) (store.CredentialState, error) {
	if !store.ValidCredentialHash(hash) || version != store.CredentialFormatVersion {
		return store.CredentialState{}, store.ErrCredentialInvalid
	}
	return scanCredentialState(s.pool.QueryRow(ctx, credentialStateSQL+` AND x.spent_at IS NULL`, hash, purpose, version))
}

// Match database timestamps at microsecond precision when constructing children.
func credentialNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now, err
}
