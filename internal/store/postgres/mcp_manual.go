package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/pgutil"
)

var _ store.MCPManualTokenStore = (*Store)(nil)

func (s *Store) CreateManualMCP(ctx context.Context, in store.MCPManualToken) (store.MCPGrant, error) {
	var g store.MCPGrant
	if in.OwnerID == uuid.Nil || in.Hours < 1 || in.Hours > 24*store.MCPConnectionDays || len(in.AccessHash) != 64 || (in.CallerID == nil && in.NewCaller == nil) {
		return g, errors.New("invalid manual MCP token")
	}
	selection := in.Selection
	if len(selection.SellerIDs) > 256 || selection.AllCampaigns != (len(selection.SellerIDs) == 0) {
		return g, errors.New("invalid MCP selection")
	}
	seen := make(map[string]bool, len(selection.SellerIDs))
	for _, seller := range selection.SellerIDs {
		id, err := uuid.Parse(seller)
		if err != nil || id.String() != seller || seen[seller] {
			return g, errors.New("invalid MCP seller")
		}
		seen[seller] = true
	}
	if s.outbox == nil {
		return g, store.ErrCallerAuditRequired
	}
	err := pgutil.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.checkMCPCapacityTx(ctx, tx, in.OwnerID); err != nil {
			return err
		}
		var single *string
		selected := slices.Clone(selection.SellerIDs)
		if len(selected) == 1 {
			single, selected = &selected[0], nil
		}
		g.OwnerID, g.MCPSelection = in.OwnerID, selection
		err := tx.QueryRow(ctx, `INSERT INTO seller_mcp_grants(owner_id,seller_id,client_id,redirect_uri,challenge,code_expires_at,access_hash,expires_at,all_campaigns,selected_ids)
 VALUES($1,$2,'','','',now(),$3,now()+make_interval(hours=>$4),$5,coalesce($6::text[],'{}')) RETURNING id,expires_at`, in.OwnerID, single, in.AccessHash, in.Hours, selection.AllCampaigns, selected).Scan(&g.ID, &g.ExpiresAt)
		if err != nil {
			return err
		}
		g.CallerID, err = s.bindCredentialCallerTx(ctx, tx, in.OwnerID, in.CallerID, in.NewCaller, caller.OAuthAccess, g.ID.String())
		if err != nil {
			return err
		}
		return s.enqueueMCP(ctx, tx, "credentials.mcp.create", g.ID, g.OwnerID, "token")
	})
	return g, err
}

// Serialize issuance across replicas using the existing owner row, independently
// of client registration. New client IDs cannot bypass the owner's capacity.
func (s *Store) checkMCPCapacityTx(ctx context.Context, tx pgx.Tx, owner uuid.UUID) error {
	var confirmed uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, owner).Scan(&confirmed); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, connectionCredentialCountSQL, owner).Scan(&count); err != nil {
		return err
	}
	if count >= store.MCPMaxActiveConnections {
		return store.ErrMCPConnectionLimit
	}
	return nil
}

func (s *Store) enqueueMCP(ctx context.Context, tx pgx.Tx, action string, id, owner uuid.UUID, method string) error {
	if s.outbox == nil {
		return nil // Legacy store callers retain their existing behavior.
	}
	state, err := json.Marshal(map[string]string{"connection_method": method, "scope": store.APIKeyScopeAnalyticsRead})
	if err != nil {
		return err
	}
	return s.enqueueAudit(ctx, tx, &audit.Event{Actor: owner.String(), Action: action, TargetType: "mcp_connection", TargetID: id.String(), ScopeType: "subject", ScopeID: owner.String(), AfterState: state})
}

// Update before taking the shared grant lock in delegation. Lock upgrades there
// can deadlock concurrent calls. At most one write per connection/hour is needed.
func touchMCP(ctx context.Context, tx pgx.Tx, accessHash string) error {
	_, err := tx.Exec(ctx, `UPDATE seller_mcp_grants SET last_used_at=now()
 WHERE (access_hash=$1 OR (session_access_hash=$1 AND access_expires_at>now())) AND expires_at>now()
 AND (last_used_at IS NULL OR last_used_at<now()-make_interval(secs=>$2))`, accessHash, time.Hour.Seconds())
	return err
}

const connectionCredentialCountSQL = `SELECT (SELECT count(*) FROM seller_mcp_grants WHERE owner_id=$1 AND expires_at>now()
 AND (coalesce(access_hash,session_access_hash) IS NOT NULL OR code_expires_at>now())) + (SELECT count(*) FROM credential_grants g WHERE owner_user_id=$1 AND credential_kind='oauth_access' AND revoked_at IS NULL AND expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM credential_secrets x WHERE x.grant_id=g.id AND x.purpose IN ('access','refresh','authorization_code') AND x.spent_at IS NULL AND x.expires_at>clock_timestamp()))`
