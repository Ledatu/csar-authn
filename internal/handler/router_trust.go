package handler

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

type routerCARegistration struct {
	ca   *x509.Certificate
	pool *x509.CertPool
}

// registerRouterCA is startup-only. Dedicated gateway ingress may share a CA
// between issuer features but must never inherit the general service trust root.
func (h *Handler) registerRouterCA(file string, listener *tls.Config) (*x509.Certificate, error) {
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
			return known.ca, nil
		}
	}
	if _, err := ca.Verify(x509.VerifyOptions{Roots: listener.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		return nil, errors.New("router CA must be separate from general service trust")
	}
	listener.ClientCAs.AddCertWithConstraint(ca, func(chain []*x509.Certificate) error {
		if len(chain) == 0 || chain[0].Subject.CommonName != sellerRouterCN {
			return errors.New("unexpected dedicated router identity")
		}
		return nil
	})
	h.routerCAs = append(h.routerCAs, routerCARegistration{ca: ca, pool: listener.ClientCAs})
	return ca, nil
}

func verifiedRouterCA(state *tls.ConnectionState, ca *x509.Certificate) bool {
	if state == nil || ca == nil {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) >= 2 && chain[0].Subject.CommonName == sellerRouterCN && chain[len(chain)-1].Equal(ca) {
			return true
		}
	}
	return false
}
