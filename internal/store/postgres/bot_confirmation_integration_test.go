package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
)

func TestBotConfirmationReplayPreservesIdentityAndConsumption(t *testing.T) {
	s := auditFixture(t)
	ctx := context.Background()
	v := &store.BotVerification{
		ID: uuid.New(), CodeHash: uuid.NewString(), Intent: "login", Status: "pending",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := s.CreateBotVerification(ctx, v); err != nil {
		t.Fatal(err)
	}

	// Exercise the real PostgreSQL pending-row race with fresh statement
	// snapshots; every repeat from the same identity must succeed.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			errs <- s.ConfirmBotVerification(ctx, v.CodeHash, "telegram", "123", "Original")
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.GetBotVerification(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmBotVerification(ctx, v.CodeHash, "telegram", "456", "Different"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("different identity accepted: %v", err)
	}
	if err := s.ConfirmBotVerification(ctx, v.CodeHash, "other", "123", "Different"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("different provider accepted: %v", err)
	}
	if _, err := s.ConsumeBotVerification(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmBotVerification(ctx, v.CodeHash, "telegram", "123", "Changed"); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetBotVerification(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "consumed" || after.ProviderDisplay != "Original" ||
		!after.ConfirmedAt.Equal(*first.ConfirmedAt) || !after.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("replay changed confirmation or expiry")
	}
	if _, err := s.ConsumeBotVerification(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay enabled a second session: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE bot_verifications SET expires_at=now()-interval '1 second' WHERE id=$1", v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmBotVerification(ctx, v.CodeHash, "telegram", "123", "Original"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired confirmation accepted: %v", err)
	}
}
