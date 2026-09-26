package legacysync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func seedLinkedUser(t *testing.T, st *mock.Store, u *store.User, links map[string]string) {
	t.Helper()
	st.SeedUser(u)
	for provider, providerUserID := range links {
		if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{Provider: provider, ProviderUserID: providerUserID, UserID: u.ID}); err != nil {
			t.Fatal(err)
		}
	}
}

func planByLegacyID(r *Report) map[int64]UserPlan {
	out := make(map[int64]UserPlan, len(r.Users))
	for _, p := range r.Users {
		out[p.LegacyID] = p
	}
	return out
}

func TestServiceDryRun(t *testing.T) {
	st := mock.New()
	carol := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	dave := uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	seedLinkedUser(t, st, &store.User{ID: alice}, map[string]string{ProviderTelegram: "111", ProviderYandex: "ya-alice-own"})
	seedLinkedUser(t, st, &store.User{ID: bob}, map[string]string{ProviderTelegram: "222"})
	seedLinkedUser(t, st, &store.User{ID: carol, Email: "carol@example.com"}, nil)
	seedLinkedUser(t, st, &store.User{ID: dave, Phone: "+79990001122"}, nil)

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	svc := NewService(st)
	svc.now = func() time.Time { return now }

	report, err := svc.DryRun(context.Background(), &Request{GeneratedAt: now, Users: []LegacyUser{
		{LegacyID: 111, TelegramID: "111", YandexID: "ya-alice-mongo"},
		{LegacyID: 222, TelegramID: "222", YandexID: "ya-bob"},
		{LegacyID: 333, TelegramID: "333", Email: "Carol@Example.com"},
		{LegacyID: 444, TelegramID: "444", Phone: "7 (999) 000-11-22"},
		{LegacyID: 555, TelegramID: "555", Email: "new@example.com", Phone: "+79990009999"},
		{LegacyID: 933839157, TelegramID: "933839157"},
	}}, Options{MaxUsers: 100, Overrides: map[int64]string{933839157: bob.String()}})
	if err != nil {
		t.Fatal(err)
	}

	plans := planByLegacyID(report)
	checks := []struct {
		legacyID int64
		action   Action
		userID   uuid.UUID
		flags    int
	}{
		{111, ActionBlocked, alice, 1},
		{222, ActionLink, bob, 0},
		{333, ActionBlocked, uuid.Nil, 1},
		{444, ActionBlocked, uuid.Nil, 1},
		{555, ActionCreate, uuid.Nil, 0},
		{933839157, ActionOverridden, bob, 0},
	}
	for _, c := range checks {
		p, ok := plans[c.legacyID]
		if !ok || p.Action != c.action || len(p.Flags) != c.flags {
			t.Fatalf("plan %d = %+v, want %s with %d flags", c.legacyID, p, c.action, c.flags)
		}
		if c.userID != uuid.Nil && p.UserID != c.userID.String() {
			t.Fatalf("plan %d user = %s, want %s", c.legacyID, p.UserID, c.userID)
		}
		if p.Action == ActionBlocked && len(p.AddLinks) > 0 {
			t.Fatalf("blocked plan %d still lists links %v", c.legacyID, p.AddLinks)
		}
	}
	if plans[111].Flags[0] != FlagProviderAlreadyLinked {
		t.Fatalf("plan 111 flags = %v", plans[111].Flags)
	}
	if plans[333].EmailTakenBy != carol.String() || plans[444].PhoneTakenBy != dave.String() {
		t.Fatalf("collisions = %+v / %+v", plans[333], plans[444])
	}
	if report.Summary.Users != 6 || report.Summary.Blocked != 3 || report.Summary.Create != 1 {
		t.Fatalf("summary = %+v", report.Summary)
	}
}

func TestServiceDryRun_OverrideToUnknownUserBlocks(t *testing.T) {
	st := mock.New()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	svc := NewService(st)
	svc.now = func() time.Time { return now }

	report, err := svc.DryRun(context.Background(), &Request{GeneratedAt: now, Users: []LegacyUser{
		{LegacyID: 933839157, TelegramID: "933839157"},
	}}, Options{MaxUsers: 10, Overrides: map[int64]string{933839157: uuid.NewString()}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OverrideUserMissing != 1 || report.Users[0].Action != ActionBlocked {
		t.Fatalf("report = %+v", report)
	}
}

func TestServiceDryRun_RejectsInvalidRequest(t *testing.T) {
	svc := NewService(mock.New())
	_, err := svc.DryRun(context.Background(), &Request{}, Options{MaxUsers: 10})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestPhoneVariants(t *testing.T) {
	if got := phoneVariants("+7 (999) 000-11-22"); len(got) != 2 || got[0] != "+79990001122" || got[1] != "79990001122" {
		t.Fatalf("variants = %v", got)
	}
	if got := phoneVariants("12345"); got != nil {
		t.Fatalf("short number variants = %v, want none", got)
	}
}
