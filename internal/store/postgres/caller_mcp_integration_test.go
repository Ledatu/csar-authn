package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func TestCallerRevocationClosesOAuthRefreshAndProofs(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	u, err := s.CreateUser(ctx, &store.User{DisplayName: "MCP caller"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "agent"}
	if err := s.CreateCaller(ctx, c, 20); err != nil {
		t.Fatal(err)
	}
	request := store.MCPRequest{ID: "request", BrowserHash: "browser", ClientID: "codex", RedirectURI: "http://127.0.0.1/callback",
		Challenge: "challenge", SessionDays: 7, CallerID: &c.ID}
	if err := s.BeginMCP(ctx, request); err != nil {
		t.Fatal(err)
	}
	decision, err := s.DecideMCP(ctx, request, u.ID, store.MCPSelection{SellerIDs: []string{uuid.NewString()}}, "code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemMCP(ctx, "code", "codex", request.RedirectURI, "challenge", "access", "refresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DelegateMCP(ctx, "access", "proof", false); err != nil {
		t.Fatal(err)
	}
	bound, err := s.CallerForCredential(ctx, u.ID, caller.OAuthAccess, decision.GrantID.String())
	if err != nil || bound.ID != c.ID {
		t.Fatal("OAuth connection lost caller binding", err)
	}
	if _, err := s.RevokeCaller(ctx, u.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMCP(ctx, "proof"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("outstanding proof survived caller revoke", err)
	}
	if _, err := s.RefreshMCP(ctx, "codex", "refresh", "new-access", "new-refresh"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("refresh survived caller revoke", err)
	}
	if _, err := s.DelegateMCP(ctx, "access", "new-proof", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("access survived caller revoke", err)
	}
}
