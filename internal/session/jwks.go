package session

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

// JWK represents a single JSON Web Key (RFC 7517 / RFC 8037).
// Matches csar's crypto.JWK struct format.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg,omitempty"`

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// OKP fields (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSHandler returns an http.Handler that serves the JWKS endpoint.
func JWKSHandler(mgr *Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kp := mgr.Keys()

		jwk, err := publicKeyToJWK(kp)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		jwks := JWKS{Keys: []JWK{*jwk}}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		json.NewEncoder(w).Encode(jwks)
	})
}

func publicKeyToJWK(kp *KeyPair) (*JWK, error) {
	pub, err := x509.ParsePKIXPublicKey(kp.PublicDER)
	if err != nil {
		return nil, err
	}

	switch key := pub.(type) {
	case ed25519.PublicKey:
		return &JWK{
			Kty: "OKP",
			Kid: kp.KID,
			Use: "sig",
			Alg: "EdDSA",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(key),
		}, nil

	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			Kid: kp.KID,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}
