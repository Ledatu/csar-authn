package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SellerMCPClient is a pre-registered public client. It never holds a secret.
type SellerMCPClient struct {
	ClientID          string   `json:"client_id"`
	RedirectURIs      []string `json:"redirect_uris"`
	AllowLoopbackPort bool     `json:"allow_loopback_port,omitempty"`
}

type sellerMCPRegistry map[string]SellerMCPClient

var sellerMCPClientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ParseSellerMCPClients decodes the optional startup-only registration list.
func ParseSellerMCPClients(raw string) ([]SellerMCPClient, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 16384 || !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		return nil, errors.New("invalid seller MCP client registration list")
	}
	var clients []SellerMCPClient
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&clients); err != nil {
		return nil, errors.New("invalid seller MCP client registration list")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("unexpected trailing seller MCP registration data")
	}
	return clients, nil
}

func newSellerMCPRegistry(clientID, redirect string, extra []SellerMCPClient) (sellerMCPRegistry, error) {
	clients := append([]SellerMCPClient(nil), extra...)
	if clientID != "" || redirect != "" {
		clients = append(clients, SellerMCPClient{ClientID: clientID, RedirectURIs: []string{redirect}})
	}
	if len(clients) > 16 {
		return nil, errors.New("too many seller MCP client registrations")
	}
	registry := make(sellerMCPRegistry, len(clients))
	for _, client := range clients {
		if !sellerMCPClientID.MatchString(client.ClientID) || strings.HasPrefix(client.ClientID, "dcr_") || len(client.RedirectURIs) == 0 || len(client.RedirectURIs) > 8 {
			return nil, errors.New("invalid seller MCP client registration")
		}
		if _, exists := registry[client.ClientID]; exists {
			return nil, errors.New("duplicate seller MCP client registration")
		}
		seen := make(map[string]bool)
		variablePort := false
		for _, uri := range client.RedirectURIs {
			if len(uri) > 2048 || !validOAuthRedirect(uri) || seen[uri] {
				return nil, errors.New("invalid seller MCP callback registration")
			}
			seen[uri] = true
			u, _ := url.Parse(uri) // validated above
			if client.AllowLoopbackPort && loopbackIP(u) && u.Port() == "" {
				variablePort = true
			}
		}
		if client.AllowLoopbackPort && !variablePort {
			return nil, errors.New("variable callback port requires a portless HTTP loopback IP registration")
		}
		client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
		registry[client.ClientID] = client
	}
	return registry, nil
}

func (clients sellerMCPRegistry) allows(clientID, redirect string) bool {
	client, ok := clients[clientID]
	if !ok || len(redirect) > 2048 || !validOAuthRedirect(redirect) {
		return false
	}
	for _, registered := range client.RedirectURIs {
		if redirect == registered {
			return true
		}
		if !client.AllowLoopbackPort {
			continue
		}
		u, _ := url.Parse(redirect)
		base, _ := url.Parse(registered)
		port, err := strconv.Atoi(u.Port())
		// RFC8252 permits the port to vary; host and escaped path remain bound.
		if loopbackIP(base) && base.Port() == "" && loopbackIP(u) &&
			u.Hostname() == base.Hostname() && u.EscapedPath() == base.EscapedPath() &&
			u.RawQuery == base.RawQuery && u.ForceQuery == base.ForceQuery &&
			err == nil && port > 0 && port <= 65535 {
			return true
		}
	}
	return false
}
