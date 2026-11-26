package handler

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

func TestIdentityImportIngressRejectsBeforeStorage(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	cfg := *h.Config()
	cfg.IdentityImport = &authnconfig.IdentityImportConfig{Version: 1, Enabled: true, RouterPeerCN: "import-router", Importers: map[string]authnconfig.IdentityImporter{"source": {Subject: "svc:importer", Source: "app", Providers: []string{"external"}, MaxUsers: 10}}}
	h.SetConfig(&cfg)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "import-router"}}
	ca := &x509.Certificate{Raw: []byte("general fixture")}
	trusted := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	good := `{"version":1,"importer":"source","source":"app","generated_at":"2026-11-26T00:00:00Z","records":[{"key":"a","identities":[]}]}`
	for _, tc := range []struct {
		name, actor, body string
		state             *tls.ConnectionState
		status            int
	}{
		{"no TLS", "svc:importer", good, nil, 403},
		{"unverified peer", "svc:importer", good, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, 403},
		{"foreign actor", "svc:foreign", good, trusted, 403},
		{"browser actor", "user", good, trusted, 403},
		{"duplicate key", "svc:importer", `{"version":1,"version":1}`, trusted, 400},
		{"unknown target authority", "svc:importer", `{"target_user_id":"arbitrary"}`, trusted, 400},
		{"source substitution", "svc:importer", `{"version":1,"importer":"source","source":"foreign"}`, trusted, 403},
		{"storage unavailable", "svc:importer", good, trusted, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/svc/authn/identity-import", bytes.NewBufferString(tc.body))
			r.TLS = tc.state
			r.Header.Set(gatewayctx.HeaderSubject, tc.actor)
			w := httptest.NewRecorder()
			h.handleIdentityImport(w, r)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
