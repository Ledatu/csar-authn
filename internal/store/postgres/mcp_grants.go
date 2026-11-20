package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

var _ store.MCPGrantStore = (*Store)(nil)

func (s *Store) BeginMCP(ctx context.Context, r store.MCPRequest) error {
	return pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM seller_mcp_requests WHERE id IN (SELECT id FROM seller_mcp_requests WHERE expires_at<=now() LIMIT 100)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM seller_mcp_grants WHERE id IN (SELECT id FROM seller_mcp_grants WHERE expires_at<=now() LIMIT 100)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO seller_mcp_requests(id,browser_hash,client_id,redirect_uri,challenge,state,expires_at) VALUES ($1,$2,$3,$4,$5,$6,now()+interval '5 minutes')`, r.ID, r.BrowserHash, r.ClientID, r.RedirectURI, r.Challenge, r.State)
		return err
	})
}

func (s *Store) DecideMCP(ctx context.Context, request store.MCPRequest, owner uuid.UUID, seller, codeHash string) (store.MCPRequest, error) {
	var r store.MCPRequest
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `DELETE FROM seller_mcp_requests WHERE id=$1 AND browser_hash=$2 AND client_id=$3 AND redirect_uri=$4 AND expires_at>now() RETURNING client_id,redirect_uri,challenge,state`, request.ID, request.BrowserHash, request.ClientID, request.RedirectURI).Scan(&r.ClientID, &r.RedirectURI, &r.Challenge, &r.State)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil || codeHash == "" {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO seller_mcp_grants(owner_id,seller_id,client_id,redirect_uri,challenge,code_hash,code_expires_at,expires_at)
  VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 minute',now()+interval '1 minute')`, owner, seller, r.ClientID, r.RedirectURI, r.Challenge, codeHash)
		return err
	})
	return r, err
}

func (s *Store) RedeemMCP(ctx context.Context, codeHash, client, redirect, challenge, accessHash string) error {
	result, err := s.pool.Exec(ctx, `UPDATE seller_mcp_grants SET code_hash=NULL,access_hash=$5,expires_at=now()+interval '1 hour'
 WHERE code_hash=$1 AND client_id=$2 AND redirect_uri=$3 AND challenge=$4 AND code_expires_at>now()`, codeHash, client, redirect, challenge, accessHash)
	if err == nil && result.RowsAffected() != 1 {
		return store.ErrNotFound
	}
	return err
}

func scanMCPGrant(row pgx.Row) (store.MCPGrant, error) {
	var g store.MCPGrant
	err := row.Scan(&g.ID, &g.OwnerID, &g.ClientID, &g.SellerID, &g.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, store.ErrNotFound
	}
	return g, err
}

func (s *Store) DelegateMCP(ctx context.Context, accessHash, delegatedHash string) (store.MCPGrant, error) {
	var g store.MCPGrant
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		g, err = scanMCPGrant(tx.QueryRow(ctx, `WITH granted AS (
    SELECT id,owner_id,client_id,seller_id,least(expires_at,now()+interval '30 seconds') AS expires_at FROM seller_mcp_grants
    WHERE access_hash=$1 AND expires_at>now() FOR KEY SHARE
   ), issued AS (INSERT INTO seller_mcp_delegations(token_hash,grant_id,expires_at)
    SELECT $2,id,expires_at FROM granted RETURNING grant_id)
   SELECT id,owner_id,client_id,seller_id::text,expires_at FROM granted JOIN issued ON grant_id=id`, accessHash, delegatedHash))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM seller_mcp_delegations WHERE token_hash IN (SELECT token_hash FROM seller_mcp_delegations WHERE expires_at<=now() LIMIT 100 FOR UPDATE SKIP LOCKED)`)
		return err
	})
	return g, err
}

func (s *Store) ConsumeMCP(ctx context.Context, delegatedHash string) (store.MCPGrant, error) {
	return scanMCPGrant(s.pool.QueryRow(ctx, `DELETE FROM seller_mcp_delegations d USING seller_mcp_grants g
  WHERE d.token_hash=$1 AND g.id=d.grant_id AND d.expires_at>now() AND g.expires_at>now()
  RETURNING g.id,g.owner_id,g.client_id,g.seller_id::text,d.expires_at`, delegatedHash))
}

func (s *Store) ListMCP(ctx context.Context, owner uuid.UUID) ([]store.MCPGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,owner_id,client_id,seller_id::text,expires_at FROM seller_mcp_grants
  WHERE owner_id=$1 AND expires_at>now() AND access_hash IS NOT NULL ORDER BY expires_at DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []store.MCPGrant{}
	for rows.Next() {
		g, err := scanMCPGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
func (s *Store) RevokeMCP(ctx context.Context, owner, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM seller_mcp_grants WHERE id=$1 AND owner_id=$2`, id, owner)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}
