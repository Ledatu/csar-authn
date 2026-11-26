package postgres

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func insertCredentialSecretTx(ctx context.Context, tx pgx.Tx, g *store.CredentialGrant, x store.CredentialSecret) error {
	x.ExpiresAt = x.ExpiresAt.UTC().Truncate(time.Microsecond)
	if x.SpentAt != nil || x.Validate(g) != nil {
		return store.ErrCredentialInvalid
	}
	var resource []byte
	var err error
	if x.Resource != nil {
		resource, err = json.Marshal(x.Resource)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO credential_secrets(id,grant_id,purpose,format_version,token_hash,created_at,expires_at,resource_ref,parent_secret_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, x.ID, x.GrantID, x.Purpose, x.FormatVersion, x.TokenHash, x.CreatedAt, x.ExpiresAt, resource, x.ParentID)
	return err
}
func credentialUseMatches(use store.CredentialUse, state *store.CredentialState) bool {
	g, x := &state.Grant, &state.Secret
	if use.OwnerID != g.OwnerID || use.CallerID != g.CallerID || use.ProfileID != g.Constraints.ProfileID || use.ProfileRevision != g.Constraints.ProfileRevision || use.Audience != g.Constraints.Audience {
		return false
	}
	if (use.Resource == nil) != (x.Resource == nil) || use.Resource != nil && *use.Resource != *x.Resource {
		return false
	}
	if x.Purpose == store.SecretCode || x.Purpose == store.SecretRefresh {
		if g.ClientBinding == nil || use.ClientID != g.ClientBinding.ClientID {
			return false
		}
		if x.Purpose == store.SecretCode && (use.RedirectURI != g.ClientBinding.RedirectURI || use.PKCEChallenge != g.ClientBinding.PKCEChallenge) {
			return false
		}
	}
	return true
}

// An access token may mint bounded proofs without being consumed. Every other
// exchange is one-use. Code/refresh redemption uses the original grant deadline;
// derived proofs are additionally bounded by the presented source's expiry.
// Refresh replay commits family revocation/audit before returning ErrCredentialReplay.
func (s *Store) ExchangeCredentialSecret(ctx context.Context, use store.CredentialUse, next []store.CredentialSecret) (store.CredentialState, error) {
	var result store.CredentialState
	if s.outbox == nil {
		return result, store.ErrCallerAuditRequired
	}
	if !store.ValidCredentialHash(use.Hash) || use.FormatVersion != store.CredentialFormatVersion {
		return result, store.ErrCredentialInvalid
	}
	replay := false
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Discover immutable lock coordinates, then acquire the common hierarchy.
		state, err := scanCredentialState(tx.QueryRow(ctx, credentialStateSQL, use.Hash, use.Purpose, use.FormatVersion))
		if err != nil {
			return err
		}
		if err := lockCredentialOwnerTx(ctx, tx, state.Grant.OwnerID); err != nil {
			return err
		}
		if err := lockCredentialCallerTx(ctx, tx, state.Grant.OwnerID, state.Grant.CallerID); err != nil {
			return err
		}
		state, err = scanCredentialState(tx.QueryRow(ctx, credentialStateSQL+` FOR UPDATE OF g,x`, use.Hash, use.Purpose, use.FormatVersion))
		if err != nil {
			return err
		}
		if !credentialUseMatches(use, &state) {
			return store.ErrCredentialInvalid
		}
		g, x := &state.Grant, &state.Secret
		if x.SpentAt != nil {
			if x.Purpose != store.SecretRefresh {
				return store.ErrNotFound
			}
			if _, err := tx.Exec(ctx, `UPDATE credential_grants SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, g.ID); err != nil {
				return err
			}
			if err := s.enqueueCredential(ctx, tx, "credentials.refresh.replay", g, x.ID); err != nil {
				return err
			}
			replay = true
			return nil
		}
		if err := validateCredentialTransition(&state, next); err != nil {
			return err
		}
		now, err := credentialNow(ctx, tx)
		if err != nil {
			return err
		}
		if !x.ExpiresAt.After(now) || !g.ExpiresAt.After(now) {
			return store.ErrNotFound
		}
		if x.Purpose != store.SecretAccess {
			if _, err := tx.Exec(ctx, `UPDATE credential_secrets SET spent_at=$2 WHERE id=$1 AND spent_at IS NULL`, x.ID, now); err != nil {
				return err
			}
		}
		if x.Purpose == store.SecretRefresh {
			// All earlier access values stop validating atomically with rotation.
			if _, err := tx.Exec(ctx, `UPDATE credential_secrets SET spent_at=$2 WHERE grant_id=$1 AND purpose='access' AND spent_at IS NULL`, g.ID, now); err != nil {
				return err
			}
		}
		for _, child := range next {
			child.CreatedAt = now
			child.ParentID = &x.ID
			if err := insertCredentialSecretTx(ctx, tx, g, child); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE credential_grants SET last_used_at=$2 WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<$2::timestamptz-interval '1 hour')`, g.ID, now); err != nil {
			return err
		}
		if err := s.enqueueCredential(ctx, tx, "credentials.secret.exchange", g, x.ID); err != nil {
			return err
		}
		result = state
		return nil
	})
	if err != nil {
		return store.CredentialState{}, err
	}
	if replay {
		return store.CredentialState{}, store.ErrCredentialReplay
	}
	return result, nil
}
func validateCredentialTransition(state *store.CredentialState, next []store.CredentialSecret) error {
	g, x := &state.Grant, &state.Secret
	switch x.Purpose {
	case store.SecretCode, store.SecretRefresh:
		if g.ClientBinding == nil {
			return store.ErrCredentialInvalid
		}
		expected := 1
		if g.ClientBinding.RefreshAllowed {
			expected = 2
		}
		if len(next) != expected {
			return store.ErrCredentialInvalid
		}
		var access, refresh int
		for _, child := range next {
			switch child.Purpose {
			case store.SecretAccess:
				access++
			case store.SecretRefresh:
				refresh++
			default:
				return store.ErrCredentialInvalid
			}
		}
		if access != 1 || refresh != expected-1 {
			return store.ErrCredentialInvalid
		}
	case store.SecretAccess:
		if len(next) != 1 || !slices.Contains([]store.SecretPurpose{store.SecretExchange, store.SecretDiscovery, store.SecretResource}, next[0].Purpose) {
			return store.ErrCredentialInvalid
		}
	case store.SecretExchange:
		if len(next) > 1 || len(next) == 1 && !slices.Contains([]store.SecretPurpose{store.SecretDiscovery, store.SecretResource}, next[0].Purpose) {
			return store.ErrCredentialInvalid
		}
	case store.SecretDiscovery:
		if len(next) > 1 || len(next) == 1 && next[0].Purpose != store.SecretResource {
			return store.ErrCredentialInvalid
		}
	case store.SecretResource:
		if len(next) != 0 {
			return store.ErrCredentialInvalid
		}
	default:
		return store.ErrCredentialInvalid
	}
	for _, child := range next {
		if child.GrantID != g.ID || child.ParentID != nil || child.SpentAt != nil {
			return store.ErrCredentialInvalid
		}
		if x.Purpose != store.SecretCode && x.Purpose != store.SecretRefresh && child.ExpiresAt.Truncate(time.Microsecond).After(x.ExpiresAt) {
			return store.ErrCredentialInvalid
		}
	}
	return nil
}
