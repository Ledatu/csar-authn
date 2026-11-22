package handler

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
)

func TestOriginIssuerRequiresDedicatedRouterAndService(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	cfg := h.cfg.Load()
	cfg.JWT.Issuer = "issuer"
	h.cfg.Store(cfg)
	ca := &x509.Certificate{Raw: []byte("dedicated")}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
	trusted := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	o := &originIssuer{handler: h, routerCA: ca}
	request := origincontext.RootRequest{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}, Receiver: "reporting", Resource: "tenant", RequestHash: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(30 * time.Second)}
	send := func(body any, state *tls.ConnectionState, service bool, handler http.HandlerFunc) *httptest.ResponseRecorder {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
		r.TLS = state
		if service {
			r.Header.Set(gatewayctx.HeaderSubject, "reporting")
			id := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "reporting", EffectiveSubject: "reporting", CredentialKind: caller.STS, Assurance: caller.Verified}
			if err := gatewayctx.SetCaller(r.Header, id); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	for _, state := range []*tls.ConnectionState{nil, {VerifiedChains: [][]*x509.Certificate{{leaf, {Raw: []byte("general")}}}}} {
		if w := send(request, state, false, o.root); w.Code != 403 {
			t.Fatal("untrusted root assertion accepted", w.Code)
		}
	}
	w := send(request, trusted, false, o.root)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("trusted root rejected", w.Code, w.Body.String())
	}
	var root origincontext.Response
	if err := json.Unmarshal(w.Body.Bytes(), &root); err != nil {
		t.Fatal(err)
	}
	lookup := func(_, _ string) (crypto.PublicKey, error) { return h.sessionMgr.Keys().PublicKey, nil }
	if _, err := origincontext.Verify(root.Token, lookup, "issuer", "reporting"); err != nil {
		t.Fatal(err)
	}
	child := origincontext.DelegateRequest{ParentToken: root.Token, Receiver: "analytics", Resource: "tenant", RequestHash: strings.Repeat("b", 64)}
	if w := send(child, trusted, false, o.delegate); w.Code != 403 {
		t.Fatal("missing service accepted")
	}
	w = send(child, trusted, true, o.delegate)
	if w.Code != 200 {
		t.Fatal("service delegation failed", w.Code, w.Body.String())
	}
	var delegated origincontext.Response
	if err := json.Unmarshal(w.Body.Bytes(), &delegated); err != nil {
		t.Fatal(err)
	}
	c, err := origincontext.Verify(delegated.Token, lookup, "issuer", "analytics")
	if err != nil || c.CheckHop("reporting", "tenant", child.RequestHash) != nil || !delegated.ExpiresAt.Equal(root.ExpiresAt) {
		t.Fatal("child changed scope/expiry", err)
	}
	child.Resource = "foreign"
	if w := send(child, trusted, true, o.delegate); w.Code != 400 {
		t.Fatal("resource expansion accepted")
	}
}

func TestOriginRegistrationIsOptInAndReusesDedicatedTrust(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	if err := h.RegisterOriginContext(http.NewServeMux(), "", nil); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(nil)
	ca := server.Certificate()
	server.Close()
	file := filepath.Join(t.TempDir(), "router.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	listener := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	if _, err := h.registerRouterCA(file, listener); err != nil {
		t.Fatal(err)
	}
	if err := h.RegisterOriginContext(http.NewServeMux(), file, listener); err != nil {
		t.Fatal("dedicated trust cannot be shared", err)
	}
	other, _, _ := newSessionsHandler(t, nil)
	if err := other.RegisterOriginContext(http.NewServeMux(), file, listener); err == nil {
		t.Fatal("general trust imported as dedicated")
	}
}
