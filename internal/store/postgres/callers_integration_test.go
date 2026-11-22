package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

func TestCallerRegistryOwnershipLimitsAndAudit(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, &store.User{DisplayName: "caller test"})
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: owner.ID, Kind: caller.Agent, Label: "test agent"}
	if err := s.CreateCaller(ctx, c, 1); err != nil {
		t.Fatal(err)
	}
	second := &store.Caller{ID: uuid.New(), OwnerID: owner.ID, Kind: caller.Application, Label: "second"}
	if err := s.CreateCaller(ctx, second, 1); !errors.Is(err, store.ErrCallerLimit) {
		t.Fatal("registration cap bypassed", err)
	}
	if items, err := s.ListActiveCallers(ctx, uuid.New()); err != nil || len(items) != 0 {
		t.Fatal("foreign owner saw caller", err)
	}
	if _, err := s.RevokeCaller(ctx, uuid.New(), c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign owner revoked caller", err)
	}
	if _, err := s.RevokeCaller(ctx, owner.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	if items, err := s.ListActiveCallers(ctx, owner.ID); err != nil || len(items) != 0 {
		t.Fatal("revoked caller remained active", err)
	}
	if err := s.CreateCaller(ctx, second, 1); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM csar_audit_outbox WHERE convert_from(payload,'UTF8')::jsonb->>'target_type'='caller'`).Scan(&events); err != nil || events != 3 {
		t.Fatal("registry mutation/audit mismatch", events, err)
	}
}

func TestCallerRegistrationRollsBackOnAuditFailure(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, &store.User{DisplayName: "rollback test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `ALTER TABLE csar_audit_outbox ADD CONSTRAINT reject_callers CHECK (convert_from(payload,'UTF8')::jsonb->>'target_type'<>'caller')`); err != nil {
		t.Fatal(err)
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: owner.ID, Kind: caller.Agent, Label: "test"}
	if err := s.CreateCaller(ctx, c, 1); err == nil {
		t.Fatal("registration succeeded without durable audit")
	}
	if items, err := s.ListActiveCallers(ctx, owner.ID); err != nil || len(items) != 0 {
		t.Fatal("unaudited caller committed", err)
	}
}

func TestCallerMutationsRequireAudit(t *testing.T) {
	s := &Store{}
	c := &store.Caller{ID: uuid.New(), OwnerID: uuid.New(), Kind: caller.Agent, Label: "test"}
	if err := s.CreateCaller(context.Background(), c, 1); !errors.Is(err, store.ErrCallerAuditRequired) {
		t.Fatal(err)
	}
}

func TestConcurrentCallerRegistrationUsesOwnerCap(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	owner, err := s.CreateUser(ctx, &store.User{DisplayName: "concurrent test"})
	if err != nil {
		t.Fatal(err)
	}
	start, results := make(chan struct{}), make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- s.CreateCaller(ctx, &store.Caller{ID: uuid.New(), OwnerID: owner.ID, Kind: caller.Agent, Label: "concurrent"}, 1)
		}()
	}
	close(start)
	one, two := <-results, <-results
	successes := 0
	for _, err := range []error{one, two} {
		if err == nil {
			successes++
		} else if !errors.Is(err, store.ErrCallerLimit) {
			t.Fatal("unexpected concurrent registration failure", err)
		}
	}
	if successes != 1 {
		t.Fatal("owner cap raced", successes)
	}
}
