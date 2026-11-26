package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetiredMCPEndpointsNotRegistered(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	for _, path := range []string{"/oauth/mcp/authorize", "/oauth/mcp/token", "/oauth/mcp/register", "/oauth/mcp/tokens", "/oauth/mcp/connections", "/oauth/mcp/requests/fixture", "/internal/seller-mcp/v1/introspect", "/svc/authn/mcp/eligible", "/internal/seller-mcp/consume-discovery", "/internal/seller-mcp/delegate-account", "/internal/seller-mcp/delegate", "/internal/seller-mcp/consume", "/oauth/mcp/consent"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			r := httptest.NewRequest(method, path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s status=%d", method, path, w.Code)
			}
		}
	}
}
