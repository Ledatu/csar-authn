package main

import (
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
)

func TestOptionalMCPFeatureFlags(t *testing.T) {
	for _, value := range []string{"", "true", "false", "invalid"} {
		t.Setenv("MCP_OAUTH_DYNAMIC_CLIENTS", value)
		got, err := optionalBoolEnv("MCP_OAUTH_DYNAMIC_CLIENTS", false)
		if (err != nil) != (value == "invalid") || got != (value == "true") {
			t.Fatalf("flag %q: %v %v", value, got, err)
		}
	}
}

func TestSellerMCPRedisIsolation(t *testing.T) {
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
			options, err := sellerMCPRedisOptions(cfg)
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
