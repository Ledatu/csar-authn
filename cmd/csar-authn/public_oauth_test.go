package main

import (
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
)

func TestRetiredFeatureFlagParsing(t *testing.T) {
	for _, value := range []string{"", "true", "false", "invalid"} {
		t.Setenv("MCP_OAUTH_DYNAMIC_CLIENTS", value)
		got, err := optionalBoolEnv("MCP_OAUTH_DYNAMIC_CLIENTS", false)
		if (err != nil) != (value == "invalid") || got != (value == "true") {
			t.Fatalf("flag %q: %v %v", value, got, err)
		}
	}
}

func TestPublicOAuthRedisIsolation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		generic      *config.RedisConfig
		address      string
		password     string
		wantAddress  string
		wantPassword string
		wantDB       int
		wantError    bool
	}{
		{name: "missing Redis", wantError: true},
		{name: "empty generic address", generic: &config.RedisConfig{}, wantError: true},
		{name: "existing configuration fallback", generic: &config.RedisConfig{Address: "existing:6379", Password: "existing-fixture", DB: 3}, wantAddress: "existing:6379", wantPassword: "existing-fixture", wantDB: 3},
		{name: "dedicated MCP keeps PostgreSQL STS", address: "redis:6379", password: "mcp-fixture", wantAddress: "redis:6379", wantPassword: "mcp-fixture"},
		{name: "dedicated MCP preserves generic Redis", generic: &config.RedisConfig{Address: "sts:6379", Password: "sts-fixture", DB: 2}, address: "redis:6379", password: "mcp-fixture", wantAddress: "redis:6379", wantPassword: "mcp-fixture"},
		{name: "partial dedicated configuration fails closed", generic: &config.RedisConfig{Address: "sts:6379"}, password: "mcp-fixture", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_OAUTH_REDIS_ADDR", tc.address)
			t.Setenv("MCP_OAUTH_REDIS_PASSWORD", tc.password)
			cfg := &config.Config{Redis: tc.generic}
			var before config.RedisConfig
			if cfg.Redis != nil {
				before = *cfg.Redis
			}
			options, err := publicOAuthRedisOptions(cfg)
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Redis != tc.generic || cfg.Redis != nil && *cfg.Redis != before {
				t.Fatal("MCP selection changed the STS Redis configuration")
			}
			if tc.wantError {
				return
			}
			if options.Addr != tc.wantAddress || options.Password != tc.wantPassword || options.DB != tc.wantDB {
				t.Fatal("wrong MCP connection selected")
			}
			if options.MaxRetries != -1 || !options.ContextTimeoutEnabled || options.PoolSize != 8 || options.PoolTimeout != 200*time.Millisecond || options.DialTimeout != time.Second || options.ReadTimeout != 200*time.Millisecond || options.WriteTimeout != 200*time.Millisecond {
				t.Fatal("MCP connection bounds changed")
			}
		})
	}
}

func TestRetiredMCPSettingsRejected(t *testing.T) {
	names := []string{"MCP_OAUTH_ENABLED", "MCP_OAUTH_DYNAMIC_CLIENTS", "MCP_OAUTH_CLIENT_ID", "MCP_OAUTH_REDIRECT_URI", "MCP_OAUTH_CLIENTS", "MCP_ROUTER_CA_FILE"}
	for _, name := range names {
		t.Setenv(name, "")
	}
	// Protected Redis aliases select a connection, never the retired protocol.
	t.Setenv("MCP_OAUTH_REDIS_ADDR", "fixture:6379")
	t.Setenv("MCP_OAUTH_REDIS_PASSWORD", "fixture")
	if err := rejectRetiredMCPSettings(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			value := "configured"
			if name == "MCP_OAUTH_ENABLED" || name == "MCP_OAUTH_DYNAMIC_CLIENTS" {
				value = "true"
			}
			t.Setenv(name, value)
			if err := rejectRetiredMCPSettings(); err == nil {
				t.Fatal("retired setting accepted")
			}
		})
	}
	for _, name := range names[:2] {
		t.Setenv(name, "false")
	}
	if err := rejectRetiredMCPSettings(); err != nil {
		t.Fatal("disabled flags should be harmless", err)
	}
	t.Setenv("MCP_OAUTH_ENABLED", "invalid")
	if err := rejectRetiredMCPSettings(); err == nil {
		t.Fatal("malformed flag accepted")
	}
}
