package store

import (
	"strings"

	"github.com/ledatu/csar-core/emailnorm"
)

// EmailProvider is the first-party email OTP provider identifier.
const EmailProvider = "email"

// NormalizeEmailString returns the canonical lowercase form of an email address.
func NormalizeEmailString(email string) (string, error) {
	return emailnorm.Normalize(email)
}

// CanonicalizeOAuthAccount normalizes email fields before account persistence.
func CanonicalizeOAuthAccount(acct *OAuthAccount) error {
	if acct == nil {
		return nil
	}
	if strings.TrimSpace(acct.Email) != "" {
		email, err := NormalizeEmailString(acct.Email)
		if err != nil {
			return err
		}
		acct.Email = email
	}
	if acct.Provider == EmailProvider {
		providerUserID, err := NormalizeEmailString(acct.ProviderUserID)
		if err != nil {
			return err
		}
		acct.ProviderUserID = providerUserID
	}
	return nil
}

// CanonicalizeUserEmail normalizes a user email value, preserving an empty email.
func CanonicalizeUserEmail(email string) (string, error) {
	if strings.TrimSpace(email) == "" {
		return "", nil
	}
	return NormalizeEmailString(email)
}
