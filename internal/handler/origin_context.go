package handler

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/origincontext"
)

type originIssuer struct {
	handler  *Handler
	routerCA *x509.Certificate
	peerCN   string
}

// RegisterOriginContext is opt-in and must run before the listener starts.
// Only the dedicated router may assert an already authenticated root principal.
func (h *Handler) RegisterOriginContext(mux *http.ServeMux, file string, listener *tls.Config) error {
	return h.RegisterOriginContextWithPeer(mux, file, sellerRouterCN, listener)
}

// RegisterOriginContextWithPeer is the explicit generic trust path. The existing
// wrapper retains its compatibility peer until application consumers migrate.
func (h *Handler) RegisterOriginContextWithPeer(mux *http.ServeMux, file, peerCN string, listener *tls.Config) error {
	if file == "" {
		return nil
	}
	ca, err := h.registerRouterTrust(file, peerCN, listener)
	if err != nil {
		return err
	}
	o := &originIssuer{handler: h, routerCA: ca, peerCN: peerCN}
	mux.HandleFunc("POST /internal/origin-context/root", o.root)
	mux.HandleFunc("POST /svc/authn/origin-context/delegate", o.delegate)
	return nil
}

func (o *originIssuer) trusted(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !verifiedRouterTrust(r.TLS, o.routerCA, o.peerCN) {
		http.Error(w, "dedicated router required", http.StatusForbidden)
		return false
	}
	return true
}

func (o *originIssuer) root(w http.ResponseWriter, r *http.Request) {
	if !o.trusted(w, r) {
		return
	}
	var request origincontext.RootRequest
	if err := httpx.ReadJSON(r, &request); err != nil {
		httpx.WriteError(w, err)
		return
	}
	result, err := origincontext.IssueRoot(o.handler.sessionMgr.Keys(), o.handler.cfg.Load().JWT.Issuer, &request)
	if err != nil {
		http.Error(w, "invalid origin context", 400)
		return
	}
	httpx.WriteJSON(w, 200, result)
}

func (o *originIssuer) delegate(w http.ResponseWriter, r *http.Request) {
	if !o.trusted(w, r) {
		return
	}
	id, err := gatewayctx.FromRequestChecked(r)
	if err != nil || id.Caller == nil || id.Caller.CallerKind != caller.Service || id.Caller.CredentialKind != caller.STS || id.Caller.CallerID != id.Subject {
		http.Error(w, "verified service hop required", http.StatusForbidden)
		return
	}
	var request origincontext.DelegateRequest
	if err := httpx.ReadJSON(r, &request); err != nil {
		httpx.WriteError(w, err)
		return
	}
	result, err := origincontext.Delegate(o.handler.sessionMgr.Keys(), o.handler.cfg.Load().JWT.Issuer, id.Subject, &request)
	if err != nil {
		http.Error(w, "invalid origin delegation", 400)
		return
	}
	httpx.WriteJSON(w, 200, result)
}
