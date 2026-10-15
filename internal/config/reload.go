package config

import (
	"errors"
	"reflect"
)

// ValidateReload checks settings whose consumers are created only at startup.
// Call it before applying any part of a new configuration. The startup config
// remains the comparison baseline even after successful partial reloads.
func ValidateReload(startup, next *Config) error {
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
