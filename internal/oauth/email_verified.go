package oauth

import "github.com/markbates/goth"

// ExtractEmailVerified determines whether the provider verified the user's email.
// Trusted providers (configured via trusted: true) always return true.
// For untrusted providers, it inspects RawData for provider-specific fields.
func ExtractEmailVerified(gothUser goth.User, trusted bool) bool {
	if trusted {
		return true
	}

	// Discord: RawData["verified"] (bool)
	if v, ok := gothUser.RawData["verified"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}

	// Google userinfo fallback: RawData["email_verified"] (bool or string)
	if v, ok := gothUser.RawData["email_verified"]; ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			return b == "true"
		}
	}

	return false
}
