package handler

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

var errMCPClientMetadata = errors.New("invalid OAuth client metadata")

func validMCPMetadataURL(raw string) bool {
	if !strings.HasPrefix(raw, "https://") || !caller.ValidClientID(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" || u.Path == "/" || u.String() != raw || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func decodeMCPClient(raw []byte, id string) (store.MCPClient, error) {
	// Explicit null capability fields must not become an implicit public-client
	// default. Absent properties and malformed declarations are different.
	var fields map[string]json.RawMessage
	if len(raw) > 65536 || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return store.MCPClient{}, errMCPClientMetadata
	}
	for _, name := range []string{"token_endpoint_auth_method", "token_endpoint_auth_methods_supported", "grant_types", "response_types"} {
		if value, present := fields[name]; present && strings.TrimSpace(string(value)) == "null" {
			return store.MCPClient{}, errMCPClientMetadata
		}
	}
	var metadata struct {
		store.MCPClient
		AuthMethods       []string        `json:"token_endpoint_auth_methods_supported"`
		Secret            json.RawMessage `json:"client_secret"`
		SecretExpiry      json.RawMessage `json:"client_secret_expires_at"`
		JWKS              json.RawMessage `json:"jwks"`
		JWKSURI           string          `json:"jwks_uri"`
		SoftwareStatement json.RawMessage `json:"software_statement"`
	}
	if len(raw) > 65536 || json.Unmarshal(raw, &metadata) != nil || metadata.Secret != nil || metadata.SecretExpiry != nil ||
		metadata.SoftwareStatement != nil || metadata.JWKS != nil && metadata.JWKSURI != "" {
		return store.MCPClient{}, errMCPClientMetadata
	}
	c := metadata.MCPClient
	if id != "" && c.ClientID != id || id == "" && c.ClientID != "" {
		return c, errMCPClientMetadata
	}
	c.ClientName = strings.TrimSpace(c.ClientName)
	if c.ClientName == "" && id == "" {
		c.ClientName = "Приложение"
	}
	if !utf8.ValidString(c.ClientName) || utf8.RuneCountInString(c.ClientName) < 1 || utf8.RuneCountInString(c.ClientName) > 80 ||
		strings.IndexFunc(c.ClientName, unicode.IsControl) >= 0 || len(c.RedirectURIs) < 1 || len(c.RedirectURIs) > 8 ||
		c.ApplicationType != "" && c.ApplicationType != "web" && c.ApplicationType != "native" {
		return c, errMCPClientMetadata
	}
	seen := make(map[string]bool)
	for _, redirect := range c.RedirectURIs {
		if len(redirect) > 2048 || !validOAuthRedirect(redirect) || seen[redirect] {
			return c, errMCPClientMetadata
		}
		seen[redirect] = true
	}
	// CIMD's plural property is authoritative. Selecting none is allowed only
	// when explicitly offered (or when both properties are absent in CIMD).
	if metadata.AuthMethods != nil {
		if len(metadata.AuthMethods) > 8 || !slices.Contains(metadata.AuthMethods, "none") ||
			c.AuthMethod != "" && !slices.Contains(metadata.AuthMethods, c.AuthMethod) {
			return c, errMCPClientMetadata
		}
		for _, method := range metadata.AuthMethods {
			if strings.HasPrefix(method, "client_secret") {
				return c, errMCPClientMetadata
			}
		}
	} else if c.AuthMethod != "" && c.AuthMethod != "none" {
		return c, errMCPClientMetadata
	}
	c.AuthMethod = "none"
	if c.GrantTypes == nil {
		c.GrantTypes = []string{"authorization_code"}
	}
	if c.ResponseTypes == nil {
		c.ResponseTypes = []string{"code"}
	}
	if len(c.GrantTypes) > 8 || len(c.ResponseTypes) > 8 || !slices.Contains(c.GrantTypes, "authorization_code") || !slices.Contains(c.ResponseTypes, "code") {
		return c, errMCPClientMetadata
	}
	refresh := slices.Contains(c.GrantTypes, "refresh_token")
	c.GrantTypes = []string{"authorization_code"}
	if refresh {
		c.GrantTypes = append(c.GrantTypes, "refresh_token")
	}
	c.ResponseTypes = []string{"code"}
	slices.Sort(c.RedirectURIs)
	// Irrelevant metadata, logos and key material are never persisted or fetched.
	c.IssuedAt = 0
	return c, nil
}
