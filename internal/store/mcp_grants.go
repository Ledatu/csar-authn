package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MCPRequest binds the browser transaction to the pre-registered client and PKCE challenge.
type MCPRequest struct{ ID, BrowserHash, ClientID, RedirectURI, Challenge, State string }
type MCPGrant struct {
	ID        uuid.UUID `json:"id"`
	OwnerID   uuid.UUID `json:"-"`
	ClientID  string    `json:"client_id"`
	SellerID  string    `json:"seller_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type MCPGrantStore interface {
	BeginMCP(context.Context, MCPRequest) error
	DecideMCP(ctx context.Context, request MCPRequest, owner uuid.UUID, seller, codeHash string) (MCPRequest, error)
	RedeemMCP(ctx context.Context, codeHash, client, redirect, challenge, accessHash string) error
	DelegateMCP(ctx context.Context, accessHash, delegatedHash string) (MCPGrant, error)
	ConsumeMCP(ctx context.Context, delegatedHash string) (MCPGrant, error)
	ListMCP(ctx context.Context, owner uuid.UUID) ([]MCPGrant, error)
	RevokeMCP(ctx context.Context, owner, id uuid.UUID) error
}
