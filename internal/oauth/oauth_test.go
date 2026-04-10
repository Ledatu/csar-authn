package oauth

import (
	"log/slog"
	"testing"

	"github.com/markbates/goth"

	"github.com/ledatu/csar-authn/internal/config"
)

func baseCfg(providers ...config.ProviderConfig) *config.Config {
	return &config.Config{
		BaseURL: "https://example.com",
		OAuth: config.OAuthConfig{
			SessionSecret: "0123456789abcdef0123456789abcdef",
			Providers:     providers,
		},
	}
}

func TestApplyGothProviders_PartialSuccess(t *testing.T) {
	logger := slog.Default()
	cfg := baseCfg(
		config.ProviderConfig{Name: "unsupported_xyz", ClientID: "id", ClientSecret: "secret"},
		config.ProviderConfig{Name: "google", ClientID: "id", ClientSecret: "secret"},
	)

	registered, err := applyGothProviders(cfg, logger)
	if err != nil {
		t.Fatalf("expected partial success, got error: %v", err)
	}
	if !registered["google"] {
		t.Error("expected google to be registered")
	}
	if registered["unsupported_xyz"] {
		t.Error("expected unsupported_xyz to NOT be registered")
	}
	if _, err := goth.GetProvider("google"); err != nil {
		t.Error("google should be retrievable from Goth")
	}
}

func TestApplyGothProviders_AllFail(t *testing.T) {
	logger := slog.Default()
	cfg := baseCfg(
		config.ProviderConfig{Name: "bogus1", ClientID: "id", ClientSecret: "secret"},
		config.ProviderConfig{Name: "bogus2", ClientID: "id", ClientSecret: "secret"},
	)

	_, err := applyGothProviders(cfg, logger)
	if err == nil {
		t.Fatal("expected error when all providers fail")
	}
}

func TestApplyGothProviders_AllSucceed(t *testing.T) {
	logger := slog.Default()
	cfg := baseCfg(
		config.ProviderConfig{Name: "google", ClientID: "id", ClientSecret: "secret"},
		config.ProviderConfig{Name: "yandex", ClientID: "id", ClientSecret: "secret"},
	)

	registered, err := applyGothProviders(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(registered) != 2 {
		t.Errorf("expected 2 registered providers, got %d", len(registered))
	}
}

func TestBuildTrustedMap_OnlyRegistered(t *testing.T) {
	cfg := baseCfg(
		config.ProviderConfig{Name: "telegram", Trusted: true, ClientID: "id", ClientSecret: "s"},
		config.ProviderConfig{Name: "google", Trusted: false, ClientID: "id", ClientSecret: "s"},
		config.ProviderConfig{Name: "yandex", Trusted: true, ClientID: "id", ClientSecret: "s"},
	)
	registered := map[string]bool{
		"google": true,
		"yandex": true,
	}

	trusted := buildTrustedMap(cfg, registered)

	if trusted["telegram"] {
		t.Error("telegram should not be trusted when not registered")
	}
	if trusted["google"] {
		t.Error("google is not configured as trusted")
	}
	if !trusted["yandex"] {
		t.Error("yandex should be trusted (configured + registered)")
	}
}

func TestNewManager_PartialProviders(t *testing.T) {
	cfg := baseCfg(
		config.ProviderConfig{Name: "unsupported_xyz", ClientID: "id", ClientSecret: "secret", Trusted: true},
		config.ProviderConfig{Name: "yandex", ClientID: "id", ClientSecret: "secret"},
	)

	mgr, err := NewManager(cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewManager should succeed with partial providers: %v", err)
	}
	if mgr.IsTrusted("unsupported_xyz") {
		t.Error("unsupported_xyz should not be trusted when it failed to register")
	}
}
