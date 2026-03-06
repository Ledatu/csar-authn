// Package session handles JWT token signing, key management, and JWKS serving.
package session

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// KeyPair holds the signing key, public key, algorithm, and key ID.
type KeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	Algorithm  string // "RS256" or "EdDSA"
	KID        string // SHA-256(DER-public-key)[:8] as hex
	PublicDER  []byte // DER-encoded public key (for JWK generation)
}

// LoadOrGenerateKeys loads keys from PEM files or auto-generates a new pair.
func LoadOrGenerateKeys(algorithm, privateKeyFile, publicKeyFile, keyDir string, autoGenerate bool, logger *slog.Logger) (*KeyPair, error) {
	// Try loading from explicit files first.
	if privateKeyFile != "" && publicKeyFile != "" {
		return loadKeysFromFiles(algorithm, privateKeyFile, publicKeyFile)
	}

	// Try loading from keyDir.
	privPath := filepath.Join(keyDir, "private.pem")
	pubPath := filepath.Join(keyDir, "public.pem")

	if fileExists(privPath) && fileExists(pubPath) {
		logger.Info("loading existing keys", "dir", keyDir)
		return loadKeysFromFiles(algorithm, privPath, pubPath)
	}

	if !autoGenerate {
		return nil, fmt.Errorf("no key files found and auto_generate is disabled")
	}

	// Generate new keys.
	logger.Info("generating new key pair", "algorithm", algorithm, "dir", keyDir)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	kp, privPEM, pubPEM, err := generateKeyPair(algorithm)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return nil, fmt.Errorf("writing public key: %w", err)
	}

	logger.Info("key pair generated", "kid", kp.KID, "algorithm", algorithm)
	return kp, nil
}

func loadKeysFromFiles(algorithm, privPath, pubPath string) (*KeyPair, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	privBlock, _ := pem.Decode(privData)
	if privBlock == nil {
		return nil, fmt.Errorf("no PEM block in private key file")
	}
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil {
		return nil, fmt.Errorf("no PEM block in public key file")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	return &KeyPair{
		PrivateKey: signer,
		PublicKey:  pubKey,
		Algorithm:  algorithm,
		KID:        computeKID(pubBlock.Bytes),
		PublicDER:  pubBlock.Bytes,
	}, nil
}

func generateKeyPair(algorithm string) (*KeyPair, []byte, []byte, error) {
	switch algorithm {
	case "RS256":
		return generateRSA()
	case "EdDSA":
		return generateEdDSA()
	default:
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func generateRSA() (*KeyPair, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating RSA key: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshalling private key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshalling public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &KeyPair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
		Algorithm:  "RS256",
		KID:        computeKID(pubBytes),
		PublicDER:  pubBytes,
	}, privPEM, pubPEM, nil
}

func generateEdDSA() (*KeyPair, []byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshalling private key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshalling public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "EdDSA",
		KID:        computeKID(pubBytes),
		PublicDER:  pubBytes,
	}, privPEM, pubPEM, nil
}

// computeKID derives a key ID from the SHA-256 hash of the DER-encoded public key.
// Returns the first 8 bytes as a 16-character hex string.
// Matches csar's ComputeKID at internal/crypto/keygen.go:141-144.
func computeKID(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return hex.EncodeToString(h[:8])
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
