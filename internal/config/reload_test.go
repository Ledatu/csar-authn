package config

import (
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/email"
	"github.com/ledatu/csar-core/secret"
	"github.com/ledatu/csar-core/ycloud"
)

func postboxReloadConfig() *Config {
	return &Config{EmailOTP: &EmailOTPConfig{
		Enabled: true, SenderAddress: "login@example.com", SenderName: "Login",
		Subject: "Sign in", CodeTTL: NewDuration(5 * time.Minute),
		Postbox: PostboxConfig{
			Endpoint: "https://postbox.cloud.yandex.net", Region: "ru-central1",
			Auth: ycloud.AuthConfig{AuthMode: "iam_token", IAMToken: secret.NewSecret("old-token")},
		},
	}}
}

func selectelReloadConfig() *Config {
	cfg := postboxReloadConfig()
	cfg.EmailOTP.Postbox = PostboxConfig{}
	cfg.EmailOTP.Delivery = &email.Config{Provider: email.ProviderSelectel, Selectel: &email.SMTPConfig{
		Host: email.SelectelHost, Port: 1127, TLSMode: email.TLSImplicit,
		Username: "smtp-user", Password: secret.NewSecret("old-password"), Timeout: NewDuration(10 * time.Second),
	}}
	return cfg
}

func TestValidateReloadRejectsFrozenEmailSettings(t *testing.T) {
	tests := []struct {
		name string
		base func() *Config
		edit func(*Config)
	}{
		{"disable", postboxReloadConfig, func(c *Config) { c.EmailOTP.Enabled = false }},
		{"remove", postboxReloadConfig, func(c *Config) { c.EmailOTP = nil }},
		{"enable", func() *Config { return &Config{} }, func(c *Config) { c.EmailOTP = postboxReloadConfig().EmailOTP }},
		{"sender_address", postboxReloadConfig, func(c *Config) { c.EmailOTP.SenderAddress = "other@example.com" }},
		{"sender_name", postboxReloadConfig, func(c *Config) { c.EmailOTP.SenderName = "Other" }},
		{"subject", postboxReloadConfig, func(c *Config) { c.EmailOTP.Subject = "Other" }},
		{"code_ttl", postboxReloadConfig, func(c *Config) { c.EmailOTP.CodeTTL = NewDuration(time.Minute) }},
		{"cooldown", postboxReloadConfig, func(c *Config) { c.EmailOTP.Cooldown = NewDuration(time.Second) }},
		{"max_attempts", postboxReloadConfig, func(c *Config) { c.EmailOTP.MaxAttempts = 2 }},
		{"pending_ip", postboxReloadConfig, func(c *Config) { c.EmailOTP.MaxPendingPerIP = 10 }},
		{"pending_email", postboxReloadConfig, func(c *Config) { c.EmailOTP.MaxPendingPerEmail = 10 }},
		{"provider", postboxReloadConfig, func(c *Config) { c.EmailOTP = selectelReloadConfig().EmailOTP }},
		{"postbox_endpoint", postboxReloadConfig, func(c *Config) { c.EmailOTP.Postbox.Endpoint = "https://other.example.com" }},
		{"postbox_region", postboxReloadConfig, func(c *Config) { c.EmailOTP.Postbox.Region = "other" }},
		{"postbox_token", postboxReloadConfig, func(c *Config) { c.EmailOTP.Postbox.Auth.IAMToken = secret.NewSecret("new-token") }},
		{"postbox_auth_mode", postboxReloadConfig, func(c *Config) {
			c.EmailOTP.Postbox.Auth = ycloud.AuthConfig{AuthMode: "service_account", SAKeyFile: "/key.json"}
		}},
		{"postbox_key_path", func() *Config {
			c := postboxReloadConfig()
			c.EmailOTP.Postbox.Auth = ycloud.AuthConfig{AuthMode: "service_account", SAKeyFile: "/old.json"}
			return c
		}, func(c *Config) { c.EmailOTP.Postbox.Auth.SAKeyFile = "/new.json" }},
		{"smtp_host", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.Host = "other.example.com" }},
		{"smtp_port", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.Port = 1126 }},
		{"smtp_tls", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.TLSMode = email.TLSStartTLS }},
		{"smtp_username", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.Username = "other-user" }},
		{"smtp_password", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.Password = secret.NewSecret("new-password") }},
		{"smtp_timeout", selectelReloadConfig, func(c *Config) { c.EmailOTP.Delivery.Selectel.Timeout = NewDuration(20 * time.Second) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startup, next := tt.base(), tt.base()
			tt.edit(next)
			err := ValidateReload(startup, next)
			if err == nil || !strings.Contains(err.Error(), "requires a restart") && !strings.Contains(err.Error(), "require a restart") {
				t.Fatalf("expected restart rejection, got %v", err)
			}
			for _, sensitive := range []string{"old-token", "new-token", "old-password", "new-password", "smtp-user", "login@example.com", "/old.json", "/new.json"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error exposed configuration value")
				}
			}
		})
	}
}

func TestValidateReloadAllowsUnrelatedChangesAndEquivalentTransport(t *testing.T) {
	for _, base := range []func() *Config{postboxReloadConfig, selectelReloadConfig} {
		startup, next := base(), base()
		next.OAuth.SessionSecret = "unrelated-oauth-change"
		if err := ValidateReload(startup, next); err != nil {
			t.Fatalf("unrelated settings rejected: %v", err)
		}
	}
	startup, next := postboxReloadConfig(), postboxReloadConfig()
	delivery := next.EmailOTP.EmailDelivery()
	next.EmailOTP.Postbox = PostboxConfig{}
	next.EmailOTP.Delivery = &delivery
	if err := ValidateReload(startup, next); err != nil {
		t.Fatalf("equivalent Postbox config rejected: %v", err)
	}
	// Comparison always uses startup, including after a successful partial reload.
	next.EmailOTP.Subject = "Changed after reload"
	if err := ValidateReload(startup, next); err == nil {
		t.Fatal("changed subject accepted after a partial reload")
	}
}

func TestValidateReloadDisabledEmailAndSessionLock(t *testing.T) {
	startup := &Config{}
	next := selectelReloadConfig()
	next.EmailOTP.Enabled = false
	if err := ValidateReload(startup, next); err != nil {
		t.Fatalf("inactive email settings rejected: %v", err)
	}
	next.LegacyUsersSync.LockDatabaseDSN = "postgres://secret@example.com/authn"
	err := ValidateReload(startup, next)
	if err == nil || err.Error() != "legacy_users_sync.lock_database_dsn requires a restart" {
		t.Fatalf("session-lock guard changed: %v", err)
	}
}
