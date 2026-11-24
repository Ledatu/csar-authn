package postgres

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func TestManualMCPResourceBindingExpiryAuditAndRevoke(t *testing.T) {
	s := auditFixture(t)
	u, err := s.CreateUser(t.Context(), &store.User{DisplayName: "manual owner"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "Analyst"}
	in := store.MCPManualToken{OwnerID: u.ID, NewCaller: c, Selection: store.MCPSelection{SellerIDs: []string{uuid.NewString()}}, AccessHash: strings.Repeat("e", 64), Hours: 24}
	g, err := s.CreateManualMCP(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if g.ClientID != "" || time.Until(g.ExpiresAt) > 24*time.Hour || time.Until(g.ExpiresAt) < 23*time.Hour {
		t.Fatal("manual credential has OAuth client or wrong deadline")
	}
	bound, err := s.CallerForCredential(t.Context(), u.ID, caller.OAuthAccess, g.ID.String())
	if err != nil || bound.ID != c.ID {
		t.Fatal("missing manual caller binding", err)
	}
	// Concurrent use must not attempt lock upgrades or move last-used on every call.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.DelegateMCP(t.Context(), in.AccessHash, fmt.Sprintf("proof-%d", i), true); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	listed, err := s.ListMCP(t.Context(), u.ID)
	if err != nil || len(listed) != 1 || listed[0].LastUsedAt == nil || len(listed[0].SellerIDs) != 1 {
		t.Fatal("manual connection not listed correctly", err)
	}
	used := *listed[0].LastUsedAt
	if _, err := s.DelegateMCP(t.Context(), in.AccessHash, "proof-later", true); err != nil {
		t.Fatal(err)
	}
	listed, err = s.ListMCP(t.Context(), u.ID)
	if err != nil || !listed[0].LastUsedAt.Equal(used) {
		t.Fatal("last-used writes are not coalesced", err)
	}
	if _, err := s.RefreshMCP(t.Context(), "", "no-refresh", "access", "refresh"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("manual token acquired refresh access", err)
	}
	if err := s.RevokeMCP(t.Context(), uuid.New(), g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross-owner revoke accepted", err)
	}
	if _, err := s.RevokeCaller(t.Context(), u.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMCP(t.Context(), "proof-later"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("manual proof survived caller revocation", err)
	}
	if _, err := s.DelegateMCP(t.Context(), in.AccessHash, "new-proof", true); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("manual access survived caller revocation", err)
	}
	var leaked int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM csar_audit_outbox WHERE convert_from(payload,'UTF8') LIKE '%' || $1 || '%'`, in.AccessHash).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("credential hash in audit", err)
	}
}

func TestManualMCPIssuanceChecksOwnerCapAndRollback(t *testing.T) {
	s := auditFixture(t)
	u, err := s.CreateUser(t.Context(), &store.User{DisplayName: "capacity owner"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Application, Label: "App"}
	if err := s.CreateCaller(t.Context(), c, 20); err != nil {
		t.Fatal(err)
	}
	in := store.MCPManualToken{OwnerID: u.ID, CallerID: &c.ID, Selection: store.MCPSelection{AllCampaigns: true}, Hours: 1}
	for i := 0; i < store.MCPMaxActiveConnections; i++ {
		in.AccessHash = fmt.Sprintf("%064x", i)
		if _, err := s.CreateManualMCP(t.Context(), in); err != nil {
			t.Fatal(err)
		}
	}
	in.AccessHash = strings.Repeat("f", 64)
	if _, err := s.CreateManualMCP(t.Context(), in); !errors.Is(err, store.ErrMCPConnectionLimit) {
		t.Fatal("owner cap bypassed", err)
	}
	in.Hours = 169
	if _, err := s.CreateManualMCP(t.Context(), in); err == nil {
		t.Fatal("unbounded lifetime accepted")
	}
	in.Hours = 1
	in.OwnerID = uuid.New()
	if _, err := s.CreateManualMCP(t.Context(), in); err == nil {
		t.Fatal("foreign caller binding accepted")
	}
}
