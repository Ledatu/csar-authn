package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/httpx"
)

const CredentialSchemaVersion = 1
const CredentialFormatVersion = 1
const CredentialAPIKeyLimit = 5
const CredentialOAuthLimit = MCPMaxActiveConnections
const MaxCredentialJSONBytes = 128 << 10

var (
	ErrCredentialInvalid = errors.New("invalid credential state or binding")
	ErrCredentialReplay  = errors.New("credential replay; family revoked")
)

type SecretPurpose string

const (
	SecretAccess    SecretPurpose = "access"
	SecretCode      SecretPurpose = "authorization_code"
	SecretRefresh   SecretPurpose = "refresh"
	SecretExchange  SecretPurpose = "exchange"
	SecretDiscovery SecretPurpose = "discovery"
	SecretResource  SecretPurpose = "resource"
)

// CredentialGrant is the sole owner/caller/consent/deadline authority. These are
// storage values, not public DTOs. New families never create legacy binding rows.
type CredentialGrant struct {
	ID, OwnerID, CallerID uuid.UUID
	SchemaVersion         int
	Kind                  caller.CredentialKind
	Constraints           authntokens.GrantConstraints
	ClientBinding         *CredentialClientBinding
	Label                 string
	CreatedAt, ExpiresAt  time.Time
	RevokedAt, LastUsedAt *time.Time
}

type CredentialClientBinding struct {
	Version        int    `json:"version"`
	ClientID       string `json:"client_id"`
	RedirectURI    string `json:"redirect_uri"`
	RefreshAllowed bool   `json:"refresh_allowed"`
	PKCEChallenge  string `json:"pkce_challenge"`
}

type CredentialSecret struct {
	ID, GrantID          uuid.UUID
	Purpose              SecretPurpose
	FormatVersion        int
	TokenHash            string
	CreatedAt, ExpiresAt time.Time
	SpentAt              *time.Time
	Resource             *authntokens.ResourceRef
	ParentID             *uuid.UUID
}

type CredentialState struct {
	Grant  CredentialGrant
	Secret CredentialSecret
}

// CredentialUse carries exact expected authority, not authority supplied by an
// untrusted caller. The issuer authenticates the request before constructing it.
// A resource proof must present its exact resource; no wildcard/namespace fallback.
type CredentialUse struct {
	Hash                                 string
	Purpose                              SecretPurpose
	FormatVersion                        int
	OwnerID, CallerID                    uuid.UUID
	ProfileID                            string
	ProfileRevision                      uint64
	Audience                             string
	Resource                             *authntokens.ResourceRef
	ClientID, RedirectURI, PKCEChallenge string
}

type CredentialAuthorizationRequest struct {
	ID                   string
	SchemaVersion        int
	BrowserHash          string
	ClientBinding        CredentialClientBinding
	ProfileID            string
	ProfileRevision      uint64
	Audience             string
	Scopes, Namespaces   []string
	State                string
	CreatedAt, ExpiresAt time.Time
	ConsumedAt           *time.Time
}

// GenericCredentialStore is opt-in; adding it does not activate generic issuers.
// Approval requires a live direct owner session at the issuer boundary (U07).
// All credential mutations require the existing transactional audit outbox.
type GenericCredentialStore interface {
	CreateCredentialGrant(context.Context, *CredentialGrant, []CredentialSecret, *Caller) error
	FindCredentialSecret(context.Context, string, SecretPurpose, int) (CredentialState, error)
	ExchangeCredentialSecret(context.Context, CredentialUse, []CredentialSecret) (CredentialState, error)
	RevokeCredentialGrant(context.Context, uuid.UUID, uuid.UUID) error
	BeginCredentialAuthorization(context.Context, CredentialAuthorizationRequest) error
	CredentialAuthorization(context.Context, string, string) (CredentialAuthorizationRequest, error)
	ApproveCredentialAuthorization(context.Context, string, string, *CredentialGrant, CredentialSecret, *Caller) error
}

func ValidCredentialHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DecodeCredentialJSON reuses the shared strict decoder, including nested unknown
// fields/case aliases, and preserves uint64 profile revisions without float casts.
func DecodeCredentialJSON(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > MaxCredentialJSONBytes {
		return ErrCredentialInvalid
	}
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(raw))}
	if httpx.ReadStrictJSON(r, value) != nil {
		return ErrCredentialInvalid
	}
	return nil
}

func (b *CredentialClientBinding) Validate() error {
	if b == nil || b.Version != 1 || !boundedCredentialText(b.ClientID, 2048, false) || !boundedCredentialText(b.RedirectURI, 2048, false) || len(b.PKCEChallenge) != 43 {
		return ErrCredentialInvalid
	}
	u, e := url.Parse(b.RedirectURI)
	if e != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil {
		return ErrCredentialInvalid
	}
	for _, c := range b.PKCEChallenge {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return ErrCredentialInvalid
		}
	}
	return nil
}
func boundedCredentialText(s string, max int, empty bool) bool {
	return (empty || s != "") && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func (g *CredentialGrant) Validate() error {
	if g == nil || g.ID == uuid.Nil || g.OwnerID == uuid.Nil || g.CallerID == uuid.Nil || g.SchemaVersion != CredentialSchemaVersion || g.Constraints.Validate() != nil || !boundedCredentialText(g.Label, 320, true) || g.CreatedAt.IsZero() || !g.ExpiresAt.After(g.CreatedAt) {
		return ErrCredentialInvalid
	}
	if g.Kind != caller.APIKey && g.Kind != caller.OAuthAccess {
		return ErrCredentialInvalid
	}
	if g.ClientBinding != nil && (g.Kind != caller.OAuthAccess || g.ClientBinding.Validate() != nil) {
		return ErrCredentialInvalid
	}
	return nil
}
func (s *CredentialSecret) Validate(g *CredentialGrant) error {
	if s == nil || g == nil || s.ID == uuid.Nil || s.GrantID != g.ID || s.FormatVersion != CredentialFormatVersion || !ValidCredentialHash(s.TokenHash) || s.CreatedAt.IsZero() || s.CreatedAt.Before(g.CreatedAt) || !s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.After(g.ExpiresAt) || s.ParentID != nil && (*s.ParentID == uuid.Nil || *s.ParentID == s.ID) {
		return ErrCredentialInvalid
	}
	switch s.Purpose {
	case SecretAccess, SecretExchange, SecretDiscovery:
		if s.Resource != nil {
			return ErrCredentialInvalid
		}
	case SecretCode, SecretRefresh:
		if g.ClientBinding == nil || s.Resource != nil || s.Purpose == SecretRefresh && !g.ClientBinding.RefreshAllowed {
			return ErrCredentialInvalid
		}
	case SecretResource:
		if s.Resource == nil || s.Resource.Validate() != nil || !slices.Contains(g.Constraints.Namespaces, s.Resource.Namespace) || g.Constraints.Selection.Mode == authntokens.Selected && !slices.Contains(g.Constraints.Selection.Resources, *s.Resource) {
			return ErrCredentialInvalid
		}
	default:
		return ErrCredentialInvalid
	}
	return nil
}
func (r *CredentialAuthorizationRequest) Validate() error {
	if r == nil || r.SchemaVersion != 1 || !authntokens.ValidProfileID(r.ID) || !ValidCredentialHash(r.BrowserHash) || r.ClientBinding.Validate() != nil || !authntokens.ValidProfileID(r.ProfileID) || r.ProfileRevision == 0 || !authntokens.ValidAudience(r.Audience) || !authntokens.ValidScopes(r.Scopes) || !authntokens.ValidNamespaces(r.Namespaces) || !boundedCredentialText(r.State, 2048, true) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.Sub(r.CreatedAt) > 5*time.Minute {
		return ErrCredentialInvalid
	}
	return nil
}
