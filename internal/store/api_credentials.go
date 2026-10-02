package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// APICredential is a seller-owned, read-only personal API credential. The raw
// token is never stored; TokenHash is the SHA-256 hex digest of its random value.
type APICredential struct {
	ID         uuid.UUID  `json:"id"`
	OwnerID    uuid.UUID  `json:"-"`
	SellerID   string     `json:"seller_id"`
	Label      string     `json:"label"`
	TokenHash  string     `json:"-"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// APICredentialStore is separate from Store so legacy test stores that do not
// exercise personal keys need no new methods.
type APICredentialStore interface {
	CreateAPICredential(ctx context.Context, key *APICredential, maxActive int) error
	ListAPICredentials(ctx context.Context, ownerID uuid.UUID) ([]APICredential, error)
	RevokeAPICredential(ctx context.Context, ownerID, keyID uuid.UUID) (*APICredential, error)
	FindAPICredentialByHash(ctx context.Context, hash string) (*APICredential, error)
}

var ErrAPICredentialLimit = errors.New("active API credential limit reached")
