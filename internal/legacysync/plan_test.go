package legacysync

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	alice = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	bob   = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
)

func TestResolveUser(t *testing.T) {
	st := State{
		Telegram: map[string]uuid.UUID{
			"111":           alice,
			"222":           bob,
			"1700000000000": bob,
		},
		Yandex: map[string]uuid.UUID{
			"ya-alice": alice,
			"ya-bob":   bob,
		},
		Overrides:        map[int64]uuid.UUID{933839157: alice},
		MissingOverrides: map[int64]struct{}{444: {}},
	}

	cases := []struct {
		name  string
		user  LegacyUser
		want  Action
		links []string
		flags []string
		owner uuid.UUID
	}{
		{"both links on one user", LegacyUser{LegacyID: 111, TelegramID: "111", YandexID: "ya-alice"}, ActionNoop, nil, nil, alice},
		{"telegram only", LegacyUser{LegacyID: 111, TelegramID: "111"}, ActionNoop, nil, nil, alice},
		{"links on different users", LegacyUser{LegacyID: 111, TelegramID: "111", YandexID: "ya-bob"}, ActionSplit, nil, nil, uuid.Nil},
		{"missing yandex link", LegacyUser{LegacyID: 111, TelegramID: "111", YandexID: "ya-new"}, ActionLink, []string{ProviderYandex}, nil, alice},
		{"missing telegram link", LegacyUser{LegacyID: 333, TelegramID: "333", YandexID: "ya-bob"}, ActionLink, []string{ProviderTelegram}, nil, bob},
		{"unknown user", LegacyUser{LegacyID: 555, TelegramID: "555", YandexID: "ya-new"}, ActionCreate, []string{ProviderTelegram, ProviderYandex}, nil, uuid.Nil},
		{"no identity", LegacyUser{LegacyID: 1800000000000}, ActionNoIdentity, nil, nil, uuid.Nil},
		{"override", LegacyUser{LegacyID: 933839157, TelegramID: "933839157"}, ActionOverridden, nil, nil, alice},
		{"override to a missing user", LegacyUser{LegacyID: 444, TelegramID: "444"}, ActionBlocked, nil, []string{FlagOverrideUserMissing}, uuid.Nil},
		{"synthetic row beside the yandex link", LegacyUser{LegacyID: 1700000000000, YandexID: "ya-bob"}, ActionNoop, nil, []string{FlagSyntheticTelegramRow}, bob},
		{"synthetic row without a yandex link", LegacyUser{LegacyID: 1700000000000, YandexID: "ya-new"}, ActionBlocked, nil, []string{FlagSyntheticTelegramRow}, uuid.Nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := resolveUser(tc.user, st)
			if p.Action != tc.want || !slices.Equal(p.AddLinks, tc.links) || !slices.Equal(p.Flags, tc.flags) {
				t.Fatalf("plan = %+v, want action %s links %v flags %v", p, tc.want, tc.links, tc.flags)
			}
			wantOwner := ""
			if tc.owner != uuid.Nil {
				wantOwner = tc.owner.String()
			}
			if p.UserID != wantOwner {
				t.Fatalf("user_id = %q, want %q", p.UserID, wantOwner)
			}
		})
	}
}

func TestResolveUser_SplitReportsBothUsers(t *testing.T) {
	p := resolveUser(LegacyUser{LegacyID: 111, TelegramID: "111", YandexID: "ya-bob"}, State{
		Telegram: map[string]uuid.UUID{"111": alice},
		Yandex:   map[string]uuid.UUID{"ya-bob": bob},
	})
	if p.TelegramUserID != alice.String() || p.YandexUserID != bob.String() {
		t.Fatalf("split plan = %+v, want both user ids", p)
	}
}

func TestBuildReport_CountsAndListsOnlyPlansNeedingAttention(t *testing.T) {
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	r := buildReport(at, []UserPlan{
		{LegacyID: 1, Action: ActionNoop, UserID: alice.String()},
		{LegacyID: 2, Action: ActionNoop, UserID: bob.String(), Flags: []string{FlagSyntheticTelegramRow}},
		{LegacyID: 3, Action: ActionCreate},
		{LegacyID: 4, Action: ActionBlocked, Flags: []string{FlagEmailTaken, FlagPhoneTaken}},
	})
	want := Summary{Users: 4, Noop: 2, Create: 1, Blocked: 1, SyntheticTelegramRows: 1, EmailTaken: 1, PhoneTaken: 1}
	if r.Summary != want || !r.DryRun || !r.GeneratedAt.Equal(at) {
		t.Fatalf("report = %+v, want summary %+v", r, want)
	}
	var listed []int64
	for _, p := range r.Users {
		listed = append(listed, p.LegacyID)
	}
	if !slices.Equal(listed, []int64{2, 3, 4}) {
		t.Fatalf("listed = %v, want [2 3 4]", listed)
	}
}

func TestRequestValidate(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	valid := func() Request {
		return Request{GeneratedAt: now, Users: []LegacyUser{{LegacyID: 1, TelegramID: "1"}, {LegacyID: 2, TelegramID: "2"}}}
	}
	if r := valid(); r.Validate(now, 10) != nil {
		t.Fatalf("valid request rejected: %v", r.Validate(now, 10))
	}

	cases := map[string]func(*Request){
		"no generated_at": func(r *Request) { r.GeneratedAt = time.Time{} },
		"future":          func(r *Request) { r.GeneratedAt = now.Add(time.Hour) },
		"no users":        func(r *Request) { r.Users = nil },
		"over the cap":    func(r *Request) { r.Users = append(r.Users, LegacyUser{LegacyID: 3}, LegacyUser{LegacyID: 4}) },
		"repeated user":   func(r *Request) { r.Users[1].LegacyID = 1 },
		"non-positive id": func(r *Request) { r.Users[0].LegacyID = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid()
			mutate(&r)
			if err := r.Validate(now, 3); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}
