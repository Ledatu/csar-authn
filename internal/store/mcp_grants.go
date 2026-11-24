package store

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
)

// MCPRequest binds the browser transaction to a validated client and PKCE challenge.
type MCPRequest struct {
	NewCaller                                                *Caller
	CallerID                                                 *uuid.UUID
	ClientName                                               string
	RefreshAllowed                                           *bool
	ID, BrowserHash, ClientID, RedirectURI, Challenge, State string
	SessionDays                                              int
}

const MCPConnectionDays = 7
const MCPAccessTTL = time.Hour

type MCPTokenLifetime struct {
	Seconds   int
	Renewable bool
}
type MCPDecision struct {
	RedirectURI, State string
	GrantID            uuid.UUID
}

// MCPSelection records the seller's consent independently of current tenant permissions.
type MCPSelection struct {
	AllCampaigns bool     `json:"all_campaigns"`
	SellerIDs    []string `json:"seller_ids"`
}

func (s MCPSelection) Allows(seller string) bool {
	return s.AllCampaigns || slices.Contains(s.SellerIDs, seller)
}

type MCPGrant struct {
	MCPSelection
	ClientName    string      `json:"client_name,omitempty"`
	CallerID      *uuid.UUID  `json:"caller_id,omitempty"`
	CallerKind    caller.Kind `json:"caller_kind,omitempty"`
	CallerLabel   string      `json:"caller_label,omitempty"`
	DiscoveryOnly bool        `json:"-"`
	ReportSeller  string      `json:"-"`
	ID            uuid.UUID   `json:"id"`
	OwnerID       uuid.UUID   `json:"-"`
	ClientID      string      `json:"client_id"`
	SellerID      string      `json:"seller_id"`
	ExpiresAt     time.Time   `json:"expires_at"`
}
type MCPGrantStore interface {
	BeginMCP(context.Context, MCPRequest) error
	MCPRequestRedirect(context.Context, MCPRequest) (string, error)
	DecideMCP(ctx context.Context, request MCPRequest, owner uuid.UUID, selection MCPSelection, codeHash string) (MCPDecision, error)
	RedeemMCP(ctx context.Context, codeHash, client, redirect, challenge, accessHash, refreshHash string) (MCPTokenLifetime, error)
	RefreshMCP(ctx context.Context, client, presentedHash, accessHash, refreshHash string) (MCPTokenLifetime, error)
	DelegateMCP(ctx context.Context, accessHash, delegatedHash string, discoveryOnly bool) (MCPGrant, error)
	ConsumeMCP(ctx context.Context, delegatedHash string) (MCPGrant, error)
	IssueMCPReport(ctx context.Context, owner, grant uuid.UUID, seller, proofHash string) error
	ActiveMCPSelection(ctx context.Context, owner, grant uuid.UUID) (MCPSelection, error)
	ListMCP(ctx context.Context, owner uuid.UUID) ([]MCPGrant, error)
	RevokeMCP(ctx context.Context, owner, id uuid.UUID) error
}
