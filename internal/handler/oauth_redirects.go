package handler

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ledatu/csar-authn/internal/store"
)

func validOAuthRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(raw, "*#") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || !uniqueParams(query) {
		return false
	}
	for _, reserved := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		if query.Has(reserved) {
			return false
		}
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
	return u.Scheme == "https" || (u.Scheme == "http" && loopback)
}

func uniqueParams(v url.Values) bool {
	for _, vs := range v {
		if len(vs) != 1 {
			return false
		}
	}
	return true
}

func publicOAuthRedirectAllowed(c store.OAuthClient, redirect string) bool {
	if len(redirect) > 2048 || !validOAuthRedirect(redirect) {
		return false
	}
	u, _ := url.Parse(redirect)
	for _, registered := range c.RedirectURIs {
		if registered == redirect {
			return true
		}
		base, err := url.Parse(registered)
		if err != nil || base == nil || !validOAuthRedirect(registered) {
			continue
		}
		nativeLocalhost := c.ApplicationType == "native" && base.Scheme == "http" && u.Scheme == "http" && base.Hostname() == "localhost" && u.Hostname() == "localhost"
		if (loopbackIP(base) && loopbackIP(u) || nativeLocalhost) && base.Hostname() == u.Hostname() &&
			base.EscapedPath() == u.EscapedPath() && base.RawQuery == u.RawQuery && base.ForceQuery == u.ForceQuery {
			return true
		}
	}
	return false
}

func loopbackIP(u *url.URL) bool {
	return u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
