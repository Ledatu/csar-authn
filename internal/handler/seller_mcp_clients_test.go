package handler

import (
	"strings"
	"testing"
)

func testMCPClients() []SellerMCPClient {
	return []SellerMCPClient{
		{ClientID: "vscode", RedirectURIs: []string{"http://127.0.0.1/", "http://127.0.0.1", "https://vscode.dev/redirect"}, AllowLoopbackPort: true},
		{ClientID: "cursor", RedirectURIs: []string{"http://localhost:8787/callback", "https://www.cursor.com/agents/mcp/oauth/callback"}},
		{ClientID: "claude", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback", "http://localhost:48974/callback", "http://127.0.0.1:48974/callback"}},
	}
}

func TestSellerMCPRegisteredCallbacks(t *testing.T) {
	clients, err := newSellerMCPRegistry("codex", "http://127.0.0.1:48973/oauth/callback", testMCPClients())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		client, redirect string
		allowed          bool
	}{
		{"codex", "http://127.0.0.1:48973/oauth/callback", true},
		{"codex", "http://127.0.0.1:48974/oauth/callback", false},
		{"vscode", "http://127.0.0.1:33418/", true},
		{"vscode", "http://127.0.0.1:59001", true},
		{"vscode", "https://vscode.dev/redirect", true},
		{"vscode", "https://insiders.vscode.dev/redirect", false},
		{"vscode", "http://localhost:33418/", false},
		{"vscode", "http://127.0.0.2:33418/", false},
		{"vscode", "http://127.0.0.1.example.com:33418/", false},
		{"vscode", "http://127.0.0.1:33418/callback", false},
		{"vscode", "http://127.0.0.1:33418/%2f", false},
		{"vscode", "http://127.0.0.1:0/", false},
		{"vscode", "http://127.0.0.1:65536/", false},
		{"vscode", "http://127.0.0.1:33418/?return=https://evil.example", false},
		{"vscode", "http://user@127.0.0.1:33418/", false},
		{"vscode", "http://127.0.0.1:33418/#fragment", false},
		{"vscode", "http://127.0.0.1:33418/#", false},
		{"vscode", "https://127.0.0.1:33418/", false},
		{"cursor", "http://localhost:8787/callback", true},
		{"cursor", "http://localhost:8788/callback", false},
		{"cursor", "https://www.cursor.com/agents/mcp/oauth/callback", true},
		{"cursor", "https://www.cursor.com.evil.example/agents/mcp/oauth/callback", false},
		{"claude", "https://claude.ai/api/mcp/auth_callback", true},
		{"claude", "http://localhost:48974/callback", true},
		{"claude", "http://127.0.0.1:48974/callback", true},
		{"claude", "http://localhost:48973/callback", false},
		{"claude", "https://claude.ai/api/mcp/auth_callback/", false},
		{"cursor", "https://claude.ai/api/mcp/auth_callback", false},
		{"aurumskynet-mcp", "http://127.0.0.1:48973/oauth/callback", false},
	} {
		t.Run(test.client+"/"+test.redirect, func(t *testing.T) {
			if clients.allows(test.client, test.redirect) != test.allowed {
				t.Fatalf("allowed=%v, want %v", !test.allowed, test.allowed)
			}
		})
	}
}

func TestSellerMCPRegistryRejectsInvalidConfiguration(t *testing.T) {
	for _, clients := range [][]SellerMCPClient{
		{{ClientID: "codex", RedirectURIs: []string{"https://example.com/callback"}}},
		{{ClientID: "bad id", RedirectURIs: []string{"https://example.com/callback"}}},
		{{ClientID: "missing-callback"}},
		{{ClientID: "duplicate", RedirectURIs: []string{"https://example.com/callback", "https://example.com/callback"}}},
		{{ClientID: "wildcard", RedirectURIs: []string{"https://*.example.com/callback"}}},
		{{ClientID: "variable-https", RedirectURIs: []string{"https://example.com/callback"}, AllowLoopbackPort: true}},
		{{ClientID: "variable-dns", RedirectURIs: []string{"http://localhost/callback"}, AllowLoopbackPort: true}},
		{{ClientID: "variable-fixed", RedirectURIs: []string{"http://127.0.0.1:1234/"}, AllowLoopbackPort: true}},
		make([]SellerMCPClient, 17),
	} {
		if _, err := newSellerMCPRegistry("codex", "http://127.0.0.1:48973/oauth/callback", clients); err == nil {
			t.Fatalf("accepted invalid registrations: %+v", clients)
		}
	}
	for _, raw := range []string{"null", `{}`, `[] {}`, `[{"client_id":"x","client_secret":"forbidden"}]`, strings.Repeat(" ", 16385)} {
		if _, err := ParseSellerMCPClients(raw); err == nil {
			t.Fatal("accepted malformed registration list")
		}
	}
	if _, err := ParseSellerMCPClients(`[{"client_id":"cursor","redirect_uris":["http://localhost:8787/callback"]}]`); err != nil {
		t.Fatal(err)
	}
}
