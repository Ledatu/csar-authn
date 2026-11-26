package handler

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sync"

	"github.com/ledatu/csar-core/authntokens"
)

type routerCARegistration struct {
	ca    *x509.Certificate
	pool  *x509.CertPool
	mu    sync.RWMutex
	peers map[string]bool
}

// registerRouterCA is startup-only. Dedicated gateway ingress may share a CA
// between issuer features but must never inherit the general service trust root.
func (h *Handler) registerRouterCA(file string, listener *tls.Config) (*x509.Certificate, error) {
	return h.registerRouterTrust(file, sellerRouterCN, listener)
}

func (h *Handler) registerRouterTrust(file, peerCN string, listener *tls.Config) (*x509.Certificate, error) {
	if !authntokens.ValidProfileID(peerCN) {
		return nil, errors.New("exact issuer ingress peer required")
	}
	if listener == nil || listener.ClientAuth != tls.RequireAndVerifyClientCert || listener.ClientCAs == nil {
		return nil, errors.New("issuer requires a verified client TLS listener")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("issuer requires one dedicated router CA")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		return nil, errors.New("invalid dedicated router CA")
	}
	for _, known := range h.routerCAs {
		if ca.Equal(known.ca) && known.pool == listener.ClientCAs {
			known.mu.Lock()
			known.peers[peerCN] = true
			known.mu.Unlock()
			return known.ca, nil
		}
	}
	if _, err := ca.Verify(x509.VerifyOptions{Roots: listener.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		return nil, errors.New("router CA must be separate from general service trust")
	}
	registration := &routerCARegistration{ca: ca, pool: listener.ClientCAs, peers: map[string]bool{peerCN: true}}
	// Transport admits the explicitly registered peers for this CA. Every issuer
	// separately checks its own immutable CA+peer pair; this union never grants
	// access to another feature merely because it shares the listener/root.
	listener.ClientCAs.AddCertWithConstraint(ca, func(chain []*x509.Certificate) error {
		registration.mu.RLock()
		defer registration.mu.RUnlock()
		if len(chain) == 0 || !registration.peers[chain[0].Subject.CommonName] {
			return errors.New("unexpected dedicated router identity")
		}
		return nil
	})
	h.routerCAs = append(h.routerCAs, registration)
	return ca, nil
}

func verifiedRouterCA(state *tls.ConnectionState, ca *x509.Certificate) bool {
	return verifiedRouterTrust(state, ca, sellerRouterCN)
}

func verifiedRouterTrust(state *tls.ConnectionState, ca *x509.Certificate, peerCN string) bool {
	if state == nil || ca == nil || !authntokens.ValidProfileID(peerCN) {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) >= 2 && chain[0].Subject.CommonName == peerCN && chain[len(chain)-1].Equal(ca) {
			return true
		}
	}
	return false
}

// The compatibility personal-key receiver belongs to general service ingress.
// A dedicated issuer CA must not inherit it by choosing the same leaf CN.
func (h *Handler) verifiedServiceRouter(state *tls.ConnectionState) bool {
	return h.verifiedGeneralPeer(state, "csar-client")
}

func (h *Handler) verifiedGeneralPeer(state *tls.ConnectionState, peerCN string) bool {
	if state == nil || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != peerCN {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) < 2 || !chain[0].Equal(state.PeerCertificates[0]) {
			continue
		}
		dedicated := false
		for _, registration := range h.routerCAs {
			if chain[len(chain)-1].Equal(registration.ca) {
				dedicated = true
				break
			}
		}
		if !dedicated {
			return true
		}
	}
	return false
}
