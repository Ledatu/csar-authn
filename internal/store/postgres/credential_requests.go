package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) BeginCredentialAuthorization(ctx context.Context, r store.CredentialAuthorizationRequest) error {
	if r.Validate() != nil || r.ConsumedAt != nil {
		return store.ErrCredentialInvalid
	}
	binding, err := json.Marshal(r.ClientBinding)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(r.Scopes)
	if err != nil {
		return err
	}
	namespaces, err := json.Marshal(r.Namespaces)
	if err != nil {
		return err
	}
	// Bound anonymous pending state across replicas without a new Redis key or
	// ownership mechanism. Expired browser transactions carry no grant authority;
	// remove at most 100 per delivery. Secret/replay history is never purged here.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE credential_authorization_requests IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM credential_authorization_requests WHERE id IN (SELECT id FROM credential_authorization_requests WHERE expires_at<=clock_timestamp() LIMIT 100)`); err != nil {
			return err
		}
		var total, client int
		if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE client_binding->>'client_id'=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()) FROM credential_authorization_requests`, r.ClientBinding.ClientID).Scan(&total, &client); err != nil {
			return err
		}
		if total >= 4096 || client >= 32 {
			return store.ErrCredentialRequestLimit
		}
		tag, err := tx.Exec(ctx, `WITH t AS (SELECT clock_timestamp() AS at) INSERT INTO credential_authorization_requests(id,schema_version,browser_hash,client_binding,profile_id,profile_revision,audience,scopes,namespaces,state,created_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,$10,at,least($11::timestamptz,at+interval '5 minutes') FROM t WHERE $11::timestamptz>at`, r.ID, r.SchemaVersion, r.BrowserHash, binding, r.ProfileID, strconv.FormatUint(r.ProfileRevision, 10), r.Audience, scopes, namespaces, r.State, r.ExpiresAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return store.ErrCredentialInvalid
		}
		return nil
	})
}

const credentialRequestSQL = `SELECT id,schema_version,browser_hash,client_binding,profile_id,profile_revision::text,audience,scopes,namespaces,state,created_at,expires_at,consumed_at FROM credential_authorization_requests WHERE id=$1 AND browser_hash=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()`

func scanCredentialRequest(row pgx.Row) (store.CredentialAuthorizationRequest, error) {
	var r store.CredentialAuthorizationRequest
	var binding, scopes, namespaces []byte
	var revision string
	err := row.Scan(&r.ID, &r.SchemaVersion, &r.BrowserHash, &binding, &r.ProfileID, &revision, &r.Audience, &scopes, &namespaces, &r.State, &r.CreatedAt, &r.ExpiresAt, &r.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, store.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if store.DecodeCredentialJSON(binding, &r.ClientBinding) != nil {
		return r, store.ErrCredentialInvalid
	}
	// Arrays contain only strings; no JSON object/number interpretation is involved.
	if json.Unmarshal(scopes, &r.Scopes) != nil || json.Unmarshal(namespaces, &r.Namespaces) != nil {
		return r, store.ErrCredentialInvalid
	}
	r.ProfileRevision, err = strconv.ParseUint(revision, 10, 64)
	if err != nil || r.Validate() != nil {
		return r, store.ErrCredentialInvalid
	}
	return r, nil
}
func (s *Store) CredentialAuthorization(ctx context.Context, id, browserHash string) (store.CredentialAuthorizationRequest, error) {
	if !store.ValidCredentialHash(browserHash) {
		return store.CredentialAuthorizationRequest{}, store.ErrCredentialInvalid
	}
	return scanCredentialRequest(s.pool.QueryRow(ctx, credentialRequestSQL, id, browserHash))
}
func (s *Store) ApproveCredentialAuthorization(ctx context.Context, id, browserHash string, g *store.CredentialGrant, code store.CredentialSecret, fresh *store.Caller) error {
	if s.outbox == nil {
		return store.ErrCallerAuditRequired
	}
	if g == nil || g.Kind != caller.OAuthAccess || g.ClientBinding == nil || code.Purpose != store.SecretCode {
		return store.ErrCredentialInvalid
	}
	copyGrant := *g
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockCredentialOwnerTx(ctx, tx, g.OwnerID); err != nil {
			return err
		}
		// Acquire the write-intent table lock before the request row. Admission
		// takes the table lock before deleting expired rows; a late lock upgrade
		// after holding the request row can deadlock with that bounded cleanup.
		if _, err := tx.Exec(ctx, `LOCK TABLE credential_authorization_requests IN ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		request, err := scanCredentialRequest(tx.QueryRow(ctx, credentialRequestSQL+` FOR UPDATE`, id, browserHash))
		if err != nil {
			return err
		}
		c := &g.Constraints
		if request.ClientBinding != *g.ClientBinding || request.ProfileID != c.ProfileID || request.ProfileRevision != c.ProfileRevision || request.Audience != c.Audience {
			return store.ErrCredentialInvalid
		}
		for _, scope := range c.Scopes {
			if !slices.Contains(request.Scopes, scope) {
				return store.ErrCredentialInvalid
			}
		}
		for _, ns := range c.Namespaces {
			if !slices.Contains(request.Namespaces, ns) {
				return store.ErrCredentialInvalid
			}
		}
		if err := s.createCredentialGrantTx(ctx, tx, &copyGrant, []store.CredentialSecret{code}, fresh); err != nil {
			return err
		}
		if err := approvePublicClientTx(ctx, tx, request.ClientBinding.ClientID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE credential_authorization_requests SET consumed_at=clock_timestamp() WHERE id=$1 AND browser_hash=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()`, id, browserHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return store.ErrNotFound
		}
		return nil
	})
	if err == nil {
		*g = copyGrant
	}
	return err
}
