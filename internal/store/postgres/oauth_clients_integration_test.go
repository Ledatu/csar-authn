package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/ledatu/csar-authn/internal/store"
)

func TestDynamicOAuthRegistrationDeduplicationAndRetention(t *testing.T) {
	s := auditFixture(t)
	c := store.OAuthClient{ClientID: "dcr_first", ClientName: "Fixture", RedirectURIs: []string{"https://client.example/callback"}, AuthMethod: "none", GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}}
	first, err := s.RegisterOAuthClient(t.Context(), c, strings.Repeat("a", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	c.ClientID = "dcr_second"
	second, err := s.RegisterOAuthClient(t.Context(), c, strings.Repeat("a", 64), 1)
	if err != nil || first.ClientID != second.ClientID {
		t.Fatal("identical metadata consumed another registration", err)
	}
	if _, err := s.RegisterOAuthClient(t.Context(), c, strings.Repeat("b", 64), 1); !errors.Is(err, store.ErrOAuthClientLimit) {
		t.Fatal("registration cap was bypassed", err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE seller_mcp_clients SET expires_at=now()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OAuthClient(t.Context(), first.ClientID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired unapproved registration accepted", err)
	}
	if _, err := s.RegisterOAuthClient(t.Context(), c, strings.Repeat("b", 64), 1); err != nil {
		t.Fatal("expired pending registration was not reclaimed", err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE seller_mcp_clients SET approved_at=now(),created_at=now()-interval '90 days'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OAuthClient(t.Context(), c.ClientID); err != nil {
		t.Fatal("approved client was removed by pending expiry", err)
	}
}
