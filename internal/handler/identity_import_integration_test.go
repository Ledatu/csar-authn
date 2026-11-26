package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/identityimport"
	"github.com/ledatu/csar-authn/internal/store/postgres"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

func TestIdentityImportNativeTLSAndTwoSourcesPG(t *testing.T) {
	f := newCredentialFixture(t)
	st, err := postgres.New(t.Context(), f.databaseURL, postgres.WithLegacyUsersSyncDSN(f.databaseURL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.EnableAuditOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := f.u.h
	h.store = st
	cfg := *h.Config()
	cfg.IdentityImport = &authnconfig.IdentityImportConfig{Version: 1, Enabled: true, RouterPeerCN: "import-router", LockDatabaseDSN: f.databaseURL, Importers: map[string]authnconfig.IdentityImporter{}}
	for _, name := range []string{"app-a", "unrelated-b"} {
		cfg.IdentityImport.Importers[name] = authnconfig.IdentityImporter{Subject: "svc:" + name, Source: name, Providers: []string{name + "-idp"}, MaxUsers: 10, Apply: authnconfig.IdentityImportApply{Enabled: true, Actions: []string{"create", "link"}, MaxCreates: 2, MaxLinks: 2}}
	}
	h.SetConfig(&cfg)
	seed := httptest.NewTLSServer(nil)
	key := seed.TLS.Certificates[0].PrivateKey.(crypto.Signer)
	seed.Close()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1000), Subject: pkix.Name{CommonName: "Import fixture root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(999), Subject: pkix.Name{CommonName: "import-router"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(h.handleIdentityImport))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	send := func(actor, path string, request identityimport.Request) (int, identityimport.Report, string) {
		t.Helper()
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(context.Background(), "POST", server.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(gatewayctx.HeaderSubject, actor)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var report identityimport.Report
		if response.StatusCode == 200 {
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, report, string(raw)
	}
	for _, name := range []string{"app-a", "unrelated-b"} {
		request := identityimport.Request{Version: 1, Importer: name, Source: name, GeneratedAt: time.Now(), Records: []identityimport.Record{{Key: "external-key", DisplayName: "PRIVATE DISPLAY", Email: name + "@example.test", Identities: []identityimport.Link{{Identity: identityimport.Identity{Provider: name + "-idp", ID: "same-opaque-id"}}}}}}
		code, report, raw := send("svc:"+name, "/svc/authn/identity-import", request)
		if code != 200 || !report.DryRun || report.Records[0].Action != "create" || strings.Contains(raw, "PRIVATE DISPLAY") || strings.Contains(raw, "@example.test") {
			t.Fatal(code, report)
		}
		code, report, _ = send("svc:"+name, "/svc/authn/identity-import?dry_run=false&actions=create", request)
		if code != 200 || report.DryRun || report.Records[0].Applied != "ok" {
			t.Fatal(code, report)
		}
		code, report, _ = send("svc:"+name, "/svc/authn/identity-import", request)
		if code != 200 || report.Records[0].Action != "noop" {
			t.Fatal(code, report)
		}
		if code, _, _ := send("svc:foreign", "/svc/authn/identity-import", request); code != 403 {
			t.Fatal("foreign service admitted", code)
		}
		request.Records[0].Identities[0].Provider = "email"
		if code, _, _ := send("svc:"+name, "/svc/authn/identity-import", request); code != 400 {
			t.Fatal("email identity assertion admitted", code)
		}
	}
}
