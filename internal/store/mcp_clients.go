package store

import (
	"context"
	"errors"
	"time"
)

var ErrMCPClientLimit = errors.New("OAuth client registration limit reached")

// MCPClient is an immutable public OAuth registration. Its display name is
// self-declared; neither registration nor a metadata URL proves software identity.
type MCPClient struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	AuthMethod      string   `json:"token_endpoint_auth_method"`
	ApplicationType string   `json:"application_type,omitempty"`
	IssuedAt        int64    `json:"client_id_issued_at,omitempty"`
}

type MCPClientStore interface {
	RegisterMCPClient(context.Context, MCPClient, string, int) (MCPClient, error)
	MCPClient(context.Context, string) (MCPClient, error)
}

type MCPRequestInfo struct {
	ClientID       string    `json:"client_id"`
	ClientName     string    `json:"client_name"`
	RedirectURI    string    `json:"redirect_uri"`
	RefreshAllowed bool      `json:"refresh_allowed"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Separate capability preserves stores that only exercise the legacy grant API.
type MCPRequestInfoStore interface {
	MCPRequestInfo(context.Context, string, string) (MCPRequestInfo, error)
}
