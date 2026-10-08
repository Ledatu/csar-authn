package oauth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/markbates/goth"
)

func TestDisabledOAuthStartsWithoutCredentialsAndDeniesFlows(t *testing.T) {
	enabled := false
	cfg := baseCfg(config.ProviderConfig{Name: "unsupported-disabled-provider"})
	cfg.OAuth.Enabled = &enabled
	cfg.OAuth.SessionSecret = ""
	mgr, err := NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatalf("disabled OAuth startup: %v", err)
	}
	if mgr.Enabled() {
		t.Fatal("OAuth must remain disabled")
	}
	handlers := []http.Handler{
		mgr.BeginAuthHandler(),
		CallbackHandler(nil, nil, nil, mgr, "", "", false, http.SameSiteLaxMode, slog.Default()),
	}
	for _, handler := range handlers {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/telegram/callback?code=ignored", nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("disabled flow status = %d", recorder.Code)
		}
	}
}

func TestReloadDisablesOAuthAndClearsRegisteredProviders(t *testing.T) {
	cfg := baseCfg(config.ProviderConfig{Name: "yandex", ClientID: "test", ClientSecret: "test"})
	mgr, err := NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	cfg.OAuth.Enabled = &enabled
	cfg.OAuth.Providers = nil
	cfg.OAuth.SessionSecret = ""
	if err := mgr.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if mgr.Enabled() {
		t.Fatal("OAuth remains enabled after reload")
	}
	if _, err := goth.GetProvider("yandex"); err == nil {
		t.Fatal("disabled provider is still registered")
	}
	cfg.OAuth.Enabled = nil
	cfg.OAuth.SessionSecret = "test-secret"
	cfg.OAuth.Providers = []config.ProviderConfig{{Name: "yandex", ClientID: "test", ClientSecret: "test"}}
	if err := mgr.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if !mgr.Enabled() {
		t.Fatal("OAuth did not resume on valid reload")
	}
}
