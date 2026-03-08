package session

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Ledatu/csar-auth/internal/config"
)

// Claims represents the JWT payload issued by csar-auth.
type Claims struct {
	Sub         string `json:"sub"`                    // user UUID
	Email       string `json:"email,omitempty"`         // user email
	DisplayName string `json:"display_name,omitempty"`  // user display name
	Iss         string `json:"iss"`                     // issuer
	Aud         string `json:"aud"`                     // audience
	Exp         int64  `json:"exp"`                     // expiration (Unix)
	Iat         int64  `json:"iat"`                     // issued at (Unix)
	Nbf         int64  `json:"nbf"`                     // not before (Unix)
}

// Manager handles JWT token signing.
type Manager struct {
	keys *KeyPair
	cfg  config.JWTConfig
}

// NewManager creates a session manager with the given key pair and config.
func NewManager(keys *KeyPair, cfg config.JWTConfig) *Manager {
	return &Manager{keys: keys, cfg: cfg}
}

// IssueToken creates a signed JWT for the given user.
func (m *Manager) IssueToken(userID, email, displayName string) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:         userID,
		Email:       email,
		DisplayName: displayName,
		Iss:         m.cfg.Issuer,
		Aud:         m.cfg.Audience,
		Iat:         now.Unix(),
		Nbf:         now.Unix(),
		Exp:         now.Add(m.cfg.TTL.Std()).Unix(),
	}

	return m.signToken(claims)
}

// TTL returns the configured token lifetime.
func (m *Manager) TTL() time.Duration {
	return m.cfg.TTL.Std()
}

// Keys returns the key pair (for JWKS handler).
func (m *Manager) Keys() *KeyPair {
	return m.keys
}

// STSClaims represents the JWT payload for STS-issued scoped tokens.
type STSClaims struct {
	Sub string   `json:"sub"` // service account name
	Iss string   `json:"iss"` // csar-auth issuer
	Aud []string `json:"aud"` // scoped audiences
	Exp int64    `json:"exp"` // expiration (Unix)
	Iat int64    `json:"iat"` // issued at (Unix)
	Nbf int64    `json:"nbf"` // not before (Unix)
}

// IssueScopedToken creates a signed JWT for an STS token exchange.
// The token contains an audience array (not a single string) for scope enforcement.
func (m *Manager) IssueScopedToken(sub string, audiences []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := STSClaims{
		Sub: sub,
		Iss: m.cfg.Issuer,
		Aud: audiences,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(ttl).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	return m.signPayload(claimsJSON)
}

func (m *Manager) signToken(claims Claims) (string, error) {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	return m.signPayload(claimsJSON)
}

// signPayload builds a JWT from pre-marshalled claims JSON.
func (m *Manager) signPayload(claimsJSON []byte) (string, error) {
	header := map[string]string{
		"alg": m.keys.Algorithm,
		"typ": "JWT",
		"kid": m.keys.KID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshalling header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	sig, err := sign([]byte(signingInput), m.keys.PrivateKey, m.keys.Algorithm)
	if err != nil {
		return "", err
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

func sign(data []byte, key crypto.Signer, alg string) ([]byte, error) {
	switch alg {
	case "RS256":
		h := crypto.SHA256.New()
		h.Write(data)
		return key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)

	case "EdDSA":
		// Ed25519 signs the raw message, not a hash.
		switch k := key.(type) {
		case ed25519.PrivateKey:
			return ed25519.Sign(k, data), nil
		default:
			return nil, fmt.Errorf("EdDSA requires ed25519.PrivateKey, got %T", key)
		}

	case "ES256":
		h := crypto.SHA256.New()
		h.Write(data)
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ES256 requires *ecdsa.PrivateKey, got %T", key)
		}
		return ecdsa.SignASN1(rand.Reader, ecKey, h.Sum(nil))

	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
}

// rsaSign signs with PKCS1v15 for RS256.
func rsaSign(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
}
