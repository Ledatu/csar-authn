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

func newApplyFixture(t *testing.T) (*Service, *mock.Store, time.Time) {
	t.Helper()
	st := mock.New()
	seedLinkedUser(t, st, &store.User{ID: alice}, map[string]string{ProviderTelegram: "111"})
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	svc := NewService(st)
	svc.now = func() time.Time { return now }
	return svc, st, now
}

func TestServiceApply_LinksAndCreatesWithoutContactData(t *testing.T) {
	svc, st, now := newApplyFixture(t)
	req := &Request{GeneratedAt: now, Users: []LegacyUser{
		{LegacyID: 111, TelegramID: "111", YandexID: "ya-alice"},
		{LegacyID: 555, TelegramID: "555", YandexID: "ya-new", FirstName: " Anna ", LastName: "Petrova", Username: "anna",
			PhotoURL: "https://t.me/i/userpic/320/a.jpg", Email: "anna@example.com", Phone: "+79990001122"},
	}}

	report, err := svc.Apply(context.Background(), req, Options{MaxUsers: 10}, ApplyOptions{
		Actions: []Action{ActionLink, ActionCreate}, MaxLinks: 5, MaxCreates: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DryRun || *report.Applied != (ApplySummary{Linked: 1, Created: 1}) {
		t.Fatalf("report = %+v applied %+v", report, report.Applied)
	}

	ctx := context.Background()
	linked, err := st.GetOAuthAccount(ctx, ProviderYandex, "ya-alice")
	if err != nil || linked.UserID != alice || linked.Email != "" || linked.EmailVerified {
		t.Fatalf("yandex link = %+v, %v", linked, err)
	}
	tg, err := st.GetOAuthAccount(ctx, ProviderTelegram, "555")
	if err != nil {
		t.Fatal(err)
	}
	if tg.ProviderMetadata["legacy_username"] != "anna" || tg.ProviderMetadata["linked_by"] != "legacy_sync" {
		t.Fatalf("telegram metadata = %v", tg.ProviderMetadata)
	}
	created, err := st.GetUserByID(ctx, tg.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if created.DisplayName != "Anna Petrova" || created.AvatarURL != "https://t.me/i/userpic/320/a.jpg" || created.Email != "" || created.Phone != "" {
		t.Fatalf("created user = %+v", created)
	}
	ya, err := st.GetOAuthAccount(ctx, ProviderYandex, "ya-new")
	if err != nil || ya.UserID != created.ID {
		t.Fatalf("created yandex link = %+v, %v", ya, err)
	}
}

func TestServiceApply_RefusesAnActionOverItsCap(t *testing.T) {
	svc, st, now := newApplyFixture(t)
	req := &Request{GeneratedAt: now, Users: []LegacyUser{
		{LegacyID: 111, TelegramID: "111", YandexID: "ya-alice"},
		{LegacyID: 555, TelegramID: "555"},
	}}

	report, err := svc.Apply(context.Background(), req, Options{MaxUsers: 10}, ApplyOptions{
		Actions: []Action{ActionLink, ActionCreate}, MaxLinks: 5, MaxCreates: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Refused) != 1 || report.Refused[0] != (Refusal{Action: ActionCreate, Planned: 1, Cap: 0}) {
		t.Fatalf("refused = %+v", report.Refused)
	}
	if report.Applied.Linked != 1 || report.Applied.Created != 0 {
		t.Fatalf("applied = %+v", report.Applied)
	}
	if _, err := st.GetOAuthAccount(context.Background(), ProviderTelegram, "555"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused create still wrote a link: %v", err)
	}
}

func TestServiceApply_OnlyRequestedActionsRun(t *testing.T) {
	svc, st, now := newApplyFixture(t)
	req := &Request{GeneratedAt: now, Users: []LegacyUser{
		{LegacyID: 111, TelegramID: "111", YandexID: "ya-alice"},
		{LegacyID: 555, TelegramID: "555"},
	}}

	report, err := svc.Apply(context.Background(), req, Options{MaxUsers: 10}, ApplyOptions{
		Actions: []Action{ActionLink}, MaxLinks: 5, MaxCreates: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if *report.Applied != (ApplySummary{Linked: 1}) {
		t.Fatalf("applied = %+v", report.Applied)
	}
	if _, err := st.GetOAuthAccount(context.Background(), ProviderTelegram, "555"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("create ran without being requested: %v", err)
	}
}

func TestServiceApply_OneRunAtATime(t *testing.T) {
	svc, st, now := newApplyFixture(t)
	release, ok, _ := st.TryLegacyUsersSyncLock(context.Background())
	if !ok {
		t.Fatal("lock not taken")
	}
	defer release()

	_, err := svc.Apply(context.Background(), &Request{GeneratedAt: now, Users: []LegacyUser{{LegacyID: 111, TelegramID: "111"}}},
		Options{MaxUsers: 10}, ApplyOptions{Actions: []Action{ActionLink}, MaxLinks: 5})
	if !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("err = %v, want ErrRunInProgress", err)
	}
}

func TestLegacyProfile(t *testing.T) {
	cases := []struct {
		user LegacyUser
		name string
		url  string
	}{
		{LegacyUser{FirstName: "Anna", Username: "anna"}, "Anna", ""},
		{LegacyUser{Username: "@anna", PhotoURL: "javascript:alert(1)"}, "@anna", ""},
		{LegacyUser{PhotoURL: "http://cdn.example/a.png"}, "", "http://cdn.example/a.png"},
		{LegacyUser{PhotoURL: "https:///no-host"}, "", ""},
	}
	for _, tc := range cases {
		got := legacyProfile(tc.user)
		if got.DisplayName != tc.name || got.AvatarURL != tc.url || got.Email != "" || got.Phone != "" {
			t.Fatalf("legacyProfile(%+v) = %+v", tc.user, got)
		}
	}
}
