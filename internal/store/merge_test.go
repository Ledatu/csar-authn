package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

func TestResolveMergeDirection_OldestWins(t *testing.T) {
	olderID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	newerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	older := &store.User{ID: olderID, CreatedAt: time.Now().Add(-time.Hour)}
	newer := &store.User{ID: newerID, CreatedAt: time.Now()}

	target, source, err := store.ResolveMergeDirection(newer, older)
	if err != nil {
		t.Fatal(err)
	}
	if target != olderID {
		t.Fatalf("target = %s, want %s", target, olderID)
	}
	if source != newerID {
		t.Fatalf("source = %s, want %s", source, newerID)
	}
}

func TestResolveMergeDirection_TieBreaksByUUID(t *testing.T) {
	now := time.Now()
	lowID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	highID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	a := &store.User{ID: highID, CreatedAt: now}
	b := &store.User{ID: lowID, CreatedAt: now}

	target, source, err := store.ResolveMergeDirection(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if target != lowID {
		t.Fatalf("target = %s, want %s", target, lowID)
	}
	if source != highID {
		t.Fatalf("source = %s, want %s", source, highID)
	}
}

func TestResolveMergeDirection_SelfMerge(t *testing.T) {
	id := uuid.New()
	user := &store.User{ID: id, CreatedAt: time.Now()}
	_, _, err := store.ResolveMergeDirection(user, user)
	if err != store.ErrSelfMerge {
		t.Fatalf("err = %v, want ErrSelfMerge", err)
	}
}

func TestResolveMergeDirection_AlreadyMerged(t *testing.T) {
	mergedInto := uuid.New()
	a := &store.User{ID: uuid.New(), CreatedAt: time.Now()}
	b := &store.User{ID: uuid.New(), CreatedAt: time.Now(), MergedInto: &mergedInto}
	_, _, err := store.ResolveMergeDirection(a, b)
	if err != store.ErrUserAlreadyMerged {
		t.Fatalf("err = %v, want ErrUserAlreadyMerged", err)
	}
}
