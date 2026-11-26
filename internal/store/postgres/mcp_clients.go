package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

var _ store.MCPClientStore = (*Store)(nil)

func (s *Store) RegisterMCPClient(ctx context.Context, client store.MCPClient, fingerprint string, cap int) (store.MCPClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var result store.MCPClient
	if cap < 1 || cap > 4096 || len(fingerprint) != 64 {
		return result, errors.New("invalid OAuth registration bounds")
	}
	raw, err := json.Marshal(client)
	if err != nil {
		return result, err
	}
	err = pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Anonymous registrations have no owner row to lock. Serialize this small,
		// rate-limited control-plane transaction to enforce a replica-wide cap.
		if _, err := tx.Exec(ctx, `LOCK TABLE seller_mcp_clients IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM seller_mcp_clients WHERE client_id IN (
 SELECT c.client_id FROM seller_mcp_clients c WHERE approved_at IS NULL AND expires_at<=now()
 AND NOT EXISTS(SELECT 1 FROM seller_mcp_requests r WHERE r.client_id=c.client_id AND r.expires_at>now())
 AND NOT EXISTS(SELECT 1 FROM credential_authorization_requests r WHERE r.client_binding->>'client_id'=c.client_id AND r.consumed_at IS NULL AND r.expires_at>now()) LIMIT 100)`); err != nil {
			return err
		}
		var stored []byte
		err := tx.QueryRow(ctx, `SELECT metadata FROM seller_mcp_clients WHERE fingerprint=$1`, fingerprint).Scan(&stored)
		if err == nil {
			if _, err := tx.Exec(ctx, `UPDATE seller_mcp_clients SET expires_at=now()+interval '24 hours' WHERE fingerprint=$1 AND approved_at IS NULL`, fingerprint); err != nil {
				return err
			}
			return json.Unmarshal(stored, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM seller_mcp_clients`).Scan(&count); err != nil {
			return err
		}
		if count >= cap {
			return store.ErrMCPClientLimit
		}
		if _, err := tx.Exec(ctx, `INSERT INTO seller_mcp_clients(client_id,fingerprint,metadata) VALUES($1,$2,$3)`, client.ClientID, fingerprint, raw); err != nil {
			return err
		}
		result = client
		return nil
	})
	return result, err
}

func (s *Store) MCPClient(ctx context.Context, id string) (store.MCPClient, error) {
	var client store.MCPClient
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT metadata FROM seller_mcp_clients WHERE client_id=$1 AND (approved_at IS NOT NULL OR expires_at>now())`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return client, store.ErrNotFound
	}
	if err != nil {
		return client, err
	}
	err = json.Unmarshal(raw, &client)
	return client, err
}

func (s *Store) MCPRequestInfo(ctx context.Context, id, browserHash string) (store.MCPRequestInfo, error) {
	var result store.MCPRequestInfo
	err := s.pool.QueryRow(ctx, `SELECT client_id,client_name,redirect_uri,refresh_allowed,expires_at FROM seller_mcp_requests WHERE id=$1 AND browser_hash=$2 AND expires_at>now()`, id, browserHash).
		Scan(&result.ClientID, &result.ClientName, &result.RedirectURI, &result.RefreshAllowed, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, store.ErrNotFound
	}
	return result, err
}

// Physical legacy table, generic public-client fields. Approval never replaces
// the immutable client/redirect/refresh snapshot on an existing grant.
func approvePublicClientTx(ctx context.Context, tx pgx.Tx, clientID string) error {
	_, err := tx.Exec(ctx, `UPDATE seller_mcp_clients SET approved_at=coalesce(approved_at,now()) WHERE client_id=$1`, clientID)
	return err
}
