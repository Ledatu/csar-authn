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

func (s *Store) DecideMCP(ctx context.Context, request store.MCPRequest, owner uuid.UUID, selection store.MCPSelection, codeHash string) (store.MCPDecision, error) {
	var r store.MCPDecision
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var challenge string
		err := tx.QueryRow(ctx, `DELETE FROM seller_mcp_requests WHERE id=$1 AND browser_hash=$2 AND client_id=$3 AND redirect_uri=$4 AND expires_at>now() RETURNING redirect_uri,challenge,state`, request.ID, request.BrowserHash, request.ClientID, request.RedirectURI).Scan(&r.RedirectURI, &challenge, &r.State)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil || codeHash == "" {
			return err
		}
		var singleton *string
		selected := selection.SellerIDs
		if len(selected) == 1 {
			singleton = &selected[0]
			selected = nil
		}
		return tx.QueryRow(ctx, `INSERT INTO seller_mcp_grants(owner_id,seller_id,client_id,redirect_uri,challenge,code_hash,code_expires_at,expires_at,all_campaigns,selected_ids)
  VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 minute',now()+interval '1 minute',$7,coalesce($8::text[],'{}')) RETURNING id`, owner, singleton, request.ClientID, r.RedirectURI, challenge, codeHash, selection.AllCampaigns, selected).Scan(&r.GrantID)
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

func scanMCPGrant(row pgx.Row, delegation bool) (store.MCPGrant, error) {
	var g store.MCPGrant
	fields := []any{&g.ID, &g.OwnerID, &g.ClientID, &g.SellerID, &g.ExpiresAt, &g.AllCampaigns, &g.SellerIDs}
	if delegation {
		fields = append(fields, &g.DiscoveryOnly, &g.ReportSeller)
	}
	err := row.Scan(fields...)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, store.ErrNotFound
	}
	if g.SellerID != "" {
		g.SellerIDs = []string{g.SellerID}
	}
	return g, err
}

func (s *Store) DelegateMCP(ctx context.Context, accessHash, delegatedHash string, discoveryOnly bool) (store.MCPGrant, error) {
	var g store.MCPGrant
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		g, err = scanMCPGrant(tx.QueryRow(ctx, `WITH granted AS (
    SELECT id,owner_id,client_id,seller_id,all_campaigns,selected_ids,least(expires_at,now()+interval '30 seconds') AS expires_at FROM seller_mcp_grants
    WHERE access_hash=$1 AND expires_at>now() FOR KEY SHARE
   ), issued AS (INSERT INTO seller_mcp_delegations(token_hash,grant_id,expires_at,discovery_only)
    SELECT $2,id,expires_at,$3 FROM granted RETURNING grant_id)
   SELECT id,owner_id,client_id,coalesce(seller_id::text,''),expires_at,all_campaigns,selected_ids FROM granted JOIN issued ON grant_id=id`, accessHash, delegatedHash, discoveryOnly), false)
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
  RETURNING g.id,g.owner_id,g.client_id,coalesce(g.seller_id::text,''),d.expires_at,g.all_campaigns,g.selected_ids,d.discovery_only,coalesce(d.report_seller::text,'')`, delegatedHash), true)
}

func (s *Store) ListMCP(ctx context.Context, owner uuid.UUID) ([]store.MCPGrant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,owner_id,client_id,coalesce(seller_id::text,''),expires_at,all_campaigns,selected_ids FROM seller_mcp_grants
  WHERE owner_id=$1 AND expires_at>now() AND access_hash IS NOT NULL ORDER BY expires_at DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []store.MCPGrant{}
	for rows.Next() {
		g, err := scanMCPGrant(rows, false)
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

func (s *Store) ActiveMCPSelection(ctx context.Context, owner, grant uuid.UUID) (store.MCPSelection, error) {
	var selection store.MCPSelection
	err := s.pool.QueryRow(ctx, `SELECT all_campaigns, CASE WHEN seller_id IS NULL THEN selected_ids ELSE ARRAY[seller_id::text] END
        FROM seller_mcp_grants WHERE id=$1 AND owner_id=$2 AND access_hash IS NOT NULL AND expires_at>now()`, grant, owner).Scan(&selection.AllCampaigns, &selection.SellerIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return selection, store.ErrNotFound
	}
	return selection, err
}

func (s *Store) IssueMCPReport(ctx context.Context, owner, grant uuid.UUID, seller, proofHash string) error {
	res, err := s.pool.Exec(ctx, `INSERT INTO seller_mcp_delegations(token_hash,grant_id,expires_at,report_seller)
        SELECT $1,id,least(expires_at,now()+interval '30 seconds'),$4::text::uuid FROM seller_mcp_grants
        WHERE id=$2 AND owner_id=$3 AND expires_at>now() AND access_hash IS NOT NULL
          AND (all_campaigns OR seller_id::text=$4 OR $4=ANY(selected_ids)) FOR KEY SHARE`, proofHash, grant, owner, seller)
	if err == nil && res.RowsAffected() != 1 {
		return store.ErrNotFound
	}
	return err
}
