package handler

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssuerPeerPoliciesStayIsolatedOnSharedCA(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	server := httptest.NewTLSServer(nil)
	ca := server.Certificate()
	key := server.TLS.Certificates[0].PrivateKey.(crypto.Signer)
	server.Close()
	file := filepath.Join(t.TempDir(), "router-ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	listener := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	legacyCA, err := h.registerRouterCA(file, listener)
	if err != nil {
		t.Fatal(err)
	}
	explicitCA, err := h.registerRouterTrust(file, "reports-router", listener)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.routerCAs) != 1 || !legacyCA.Equal(explicitCA) {
		t.Fatal("root registration duplicated")
	}
	mux := http.NewServeMux()
	if err := h.RegisterOriginContextWithPeer(mux, file, "reports-router", listener); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{sellerRouterCN, "reports-router", "unknown-router"} {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 10)), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chains, err := cert.Verify(x509.VerifyOptions{Roots: listener.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if name == "unknown-router" {
			if err == nil {
				t.Fatal("unconfigured transport peer accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal("configured transport peer rejected", err)
		}
		state := &tls.ConnectionState{VerifiedChains: chains}
		if verifiedRouterCA(state, legacyCA) != (name == sellerRouterCN) {
			t.Fatal("legacy feature peer policy broadened")
		}
		if verifiedRouterTrust(state, explicitCA, "reports-router") != (name == "reports-router") {
			t.Fatal("explicit feature inherited another peer")
		}
		r := httptest.NewRequest("POST", "/internal/origin-context/root", strings.NewReader(`{}`))
		r.TLS = state
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		expected := http.StatusForbidden
		if name == "reports-router" {
			expected = http.StatusBadRequest
		}
		if w.Code != expected {
			t.Fatal("configured origin endpoint accepted another feature peer", w.Code)
		}
		foreign := &x509.Certificate{Raw: []byte("foreign CA")}
		if verifiedRouterTrust(state, foreign, name) {
			t.Fatal("wrong configured root accepted")
		}
	}
	if err := h.RegisterOriginContextWithPeer(http.NewServeMux(), file, "*", listener); err == nil {
		t.Fatal("wildcard peer accepted")
	}
}
