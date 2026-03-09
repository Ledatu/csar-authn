// Package session handles JWT token signing, key management, and JWKS serving.
package session

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ledatu/csar-core/jwtx"
)

// KeyPair holds the signing key, public key, algorithm, and key ID.
// Wraps jwtx.KeyPair with the same public fields for backward compatibility.
type KeyPair = jwtx.KeyPair

// LoadOrGenerateKeys loads keys from PEM files or auto-generates a new pair.
func LoadOrGenerateKeys(algorithm, privateKeyFile, publicKeyFile, keyDir string, autoGenerate bool, logger *slog.Logger) (*KeyPair, error) {
	if privateKeyFile != "" && publicKeyFile != "" {
		return jwtx.LoadKeyPairFromPEM(privateKeyFile, publicKeyFile)
	}

	privPath := keyDir + "/private.pem"
	pubPath := keyDir + "/public.pem"

	if fileExists(privPath) && fileExists(pubPath) {
		logger.Info("loading existing keys", "dir", keyDir)
		return jwtx.LoadKeyPairFromPEM(privPath, pubPath)
	}

	if !autoGenerate {
		return nil, fmt.Errorf("no key files found and auto_generate is disabled")
	}

	logger.Info("generating new key pair", "algorithm", algorithm, "dir", keyDir)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	kp, err := jwtx.GenerateKeyPair(algorithm)
	if err != nil {
		return nil, err
	}

	privPEM, pubPEM, err := jwtx.MarshalKeyPairPEM(kp)
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
