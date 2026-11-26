package store

import (
	"context"
	"errors"
)

var ErrOAuthClientLimit = errors.New("OAuth client registration limit reached")

// OAuthClient is an immutable public OAuth registration. Its display name is
// self-declared; neither registration nor a metadata URL proves software identity.
type OAuthClient struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	RedirectURIs    []string `json:"redirect_uris"`
	GrantTypes      []string `json:"grant_types"`
	ResponseTypes   []string `json:"response_types"`
	AuthMethod      string   `json:"token_endpoint_auth_method"`
	ApplicationType string   `json:"application_type,omitempty"`
	IssuedAt        int64    `json:"client_id_issued_at,omitempty"`
}

type OAuthClientStore interface {
	RegisterOAuthClient(context.Context, OAuthClient, string, int) (OAuthClient, error)
	OAuthClient(context.Context, string) (OAuthClient, error)
}
