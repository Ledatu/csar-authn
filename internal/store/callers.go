package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
)

// Caller is an owner-registered agent/application, independent of its keys or
// OAuth connections. Human and service principals retain their issuer stores.
type Caller struct {
	ID        uuid.UUID   `json:"id"`
	OwnerID   uuid.UUID   `json:"-"`
	Kind      caller.Kind `json:"caller_kind"`
	Label     string      `json:"label"`
	CreatedAt time.Time   `json:"created_at"`
	RevokedAt *time.Time  `json:"revoked_at,omitempty"`
}

// CallerRegistryStore mutations require transactional audit. Kind and ownership
// are immutable. Listing is active-only, bounded by the registration cap (100).
type CallerRegistryStore interface {
	CreateCaller(context.Context, *Caller, int) error
	ListActiveCallers(context.Context, uuid.UUID) ([]Caller, error)
	RevokeCaller(context.Context, uuid.UUID, uuid.UUID) (*Caller, error)
}

// CallerCredentialStore resolves an already authenticated credential.
// ErrNotFound means unregistered legacy input, never an inferred caller kind.
type CallerCredentialStore interface {
	CallerForCredential(context.Context, uuid.UUID, caller.CredentialKind, string) (*Caller, error)
}

var (
	ErrCallerLimit         = errors.New("active caller limit reached")
	ErrCallerAuditRequired = errors.New("caller mutations require transactional audit")
	ErrCallerBinding       = errors.New("credential caller binding is inconsistent")
)

func (c *Caller) ValidateRegistration() error {
	if c == nil || c.ID == uuid.Nil || c.OwnerID == uuid.Nil {
		return errors.New("caller and owner IDs are required")
	}
	if c.Kind != caller.Agent && c.Kind != caller.Application {
		return errors.New("registered caller must be an agent or application")
	}
	c.Label = strings.TrimSpace(c.Label)
	if !utf8.ValidString(c.Label) || utf8.RuneCountInString(c.Label) < 1 || utf8.RuneCountInString(c.Label) > 80 ||
		strings.IndexFunc(c.Label, unicode.IsControl) >= 0 {
		return errors.New("caller label must contain 1-80 characters without controls")
	}
	return nil
}
