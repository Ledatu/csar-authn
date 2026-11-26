package config

import (
	"errors"
	"reflect"
)

// ValidateReload checks settings whose consumers are created only at startup.
// Call it before applying any part of a new configuration. The startup config
// remains the comparison baseline even after successful partial reloads.
func ValidateReload(startup, next *Config) error {
	credentialEnabled := startup.Credentials != nil && startup.Credentials.Enabled
	importEnabled := startup.IdentityImport != nil && startup.IdentityImport.Enabled
	if (credentialEnabled || importEnabled) && (!reflect.DeepEqual(startup.Cookie, next.Cookie) || !reflect.DeepEqual(startup.TLS, next.TLS)) {
		return errors.New("credential/import session and TLS settings require a restart")
	}
	if !reflect.DeepEqual(startup.BrowserDirectory, next.BrowserDirectory) || !reflect.DeepEqual(startup.IdentityImport, next.IdentityImport) {
		return errors.New("directory and identity import policy require a restart")
	}
	if next.AuditOutboxEnabled != startup.AuditOutboxEnabled {
		return errors.New("audit_outbox_enabled requires a restart")
	}
	if next.OriginRouterCAFile != startup.OriginRouterCAFile {
		return errors.New("origin_router_ca_file requires a restart")
	}
	if next.OriginRouterPeerCN != startup.OriginRouterPeerCN || !reflect.DeepEqual(startup.Credentials, next.Credentials) {
		return errors.New("issuer peer and credential profile settings require a restart")
	}
	if next.LegacyUsersSync.LockDatabaseDSN != startup.LegacyUsersSync.LockDatabaseDSN {
		return errors.New("legacy_users_sync.lock_database_dsn requires a restart")
	}

	wasEnabled := startup.EmailOTP != nil && startup.EmailOTP.Enabled
	isEnabled := next.EmailOTP != nil && next.EmailOTP.Enabled
	if wasEnabled != isEnabled {
		return errors.New("email_otp.enabled requires a restart")
	}
	if !wasEnabled {
		return nil
	}

	// Normalize transport syntax but retain every OTP setting: the sender,
	// routes and emailotp.Handler all capture their configuration at startup.
	// DeepEqual compares secret.Secret values without serializing them through
	// redacting marshalers.
	if !reflect.DeepEqual(effectiveEmailOTP(startup.EmailOTP), effectiveEmailOTP(next.EmailOTP)) {
		return errors.New("email_otp settings require a restart")
	}
	return nil
}

func effectiveEmailOTP(cfg *EmailOTPConfig) EmailOTPConfig {
	effective := *cfg
	delivery := cfg.EmailDelivery()
	effective.Postbox = PostboxConfig{}
	effective.Delivery = &delivery
	return effective
}
