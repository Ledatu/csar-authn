package legacysync

import (
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	ProviderTelegram = "telegram"
	ProviderYandex   = "yandex"
)

type Action string

const (
	ActionNoop       Action = "noop"
	ActionCreate     Action = "create"
	ActionLink       Action = "link"
	ActionSplit      Action = "split_identity"
	ActionOverridden Action = "overridden"
	ActionBlocked    Action = "blocked"
	ActionNoIdentity Action = "no_identity"
)

const (
	FlagSyntheticTelegramRow  = "synthetic_telegram_row"
	FlagEmailTaken            = "email_taken"
	FlagPhoneTaken            = "phone_taken"
	FlagProviderAlreadyLinked = "provider_already_linked"
	FlagOverrideUserMissing   = "override_user_missing"
)

// UserPlan never carries profile data, email or phone: reports are stored on
// the exporter host.
type UserPlan struct {
	LegacyID                int64    `json:"legacy_id"`
	Action                  Action   `json:"action"`
	UserID                  string   `json:"user_id,omitempty"`
	TelegramUserID          string   `json:"telegram_user_id,omitempty"`
	YandexUserID            string   `json:"yandex_user_id,omitempty"`
	AddLinks                []string `json:"add_links,omitempty"`
	Flags                   []string `json:"flags,omitempty"`
	SyntheticTelegramUserID string   `json:"synthetic_telegram_user_id,omitempty"`
	EmailTakenBy            string   `json:"email_taken_by,omitempty"`
	PhoneTakenBy            string   `json:"phone_taken_by,omitempty"`
}

func (p *UserPlan) block(flag string) {
	p.Action = ActionBlocked
	p.Flags = append(p.Flags, flag)
}

// State is what authn already knows about the requested identities. Link maps
// hold canonical (post-merge) user ids.
type State struct {
	Telegram         map[string]uuid.UUID
	Yandex           map[string]uuid.UUID
	Overrides        map[int64]uuid.UUID
	MissingOverrides map[int64]struct{}
}

func resolveUser(u LegacyUser, st State) UserPlan {
	p := UserPlan{LegacyID: u.LegacyID}
	if u.TelegramID == "" {
		if id, ok := st.Telegram[syntheticTelegramID(u.LegacyID)]; ok {
			p.SyntheticTelegramUserID = id.String()
			p.Flags = append(p.Flags, FlagSyntheticTelegramRow)
		}
	}
	if _, missing := st.MissingOverrides[u.LegacyID]; missing {
		p.block(FlagOverrideUserMissing)
		return p
	}
	if id, ok := st.Overrides[u.LegacyID]; ok {
		p.Action, p.UserID = ActionOverridden, id.String()
		return p
	}

	tg, tgOK := lookup(st.Telegram, u.TelegramID)
	ya, yaOK := lookup(st.Yandex, u.YandexID)
	if tgOK {
		p.TelegramUserID = tg.String()
	}
	if yaOK {
		p.YandexUserID = ya.String()
	}

	switch {
	case u.TelegramID == "" && u.YandexID == "":
		p.Action = ActionNoIdentity
	case tgOK && yaOK && tg != ya:
		p.Action = ActionSplit
	case tgOK && u.YandexID != "" && !yaOK:
		p.Action, p.UserID, p.AddLinks = ActionLink, tg.String(), []string{ProviderYandex}
	case yaOK && u.TelegramID != "" && !tgOK:
		p.Action, p.UserID, p.AddLinks = ActionLink, ya.String(), []string{ProviderTelegram}
	case tgOK:
		p.Action, p.UserID = ActionNoop, tg.String()
	case yaOK:
		p.Action, p.UserID = ActionNoop, ya.String()
	case p.SyntheticTelegramUserID != "":
		p.Action = ActionBlocked
	default:
		p.Action, p.AddLinks = ActionCreate, legacyProviders(u)
	}
	return p
}

func syntheticTelegramID(legacyID int64) string {
	return strconv.FormatInt(legacyID, 10)
}

func lookup(links map[string]uuid.UUID, providerUserID string) (uuid.UUID, bool) {
	if providerUserID == "" {
		return uuid.Nil, false
	}
	id, ok := links[providerUserID]
	return id, ok
}

func legacyProviders(u LegacyUser) []string {
	var providers []string
	if u.TelegramID != "" {
		providers = append(providers, ProviderTelegram)
	}
	if u.YandexID != "" {
		providers = append(providers, ProviderYandex)
	}
	return providers
}

type Summary struct {
	Users                 int `json:"users"`
	Noop                  int `json:"noop"`
	Create                int `json:"create"`
	Link                  int `json:"link"`
	SplitIdentity         int `json:"split_identity"`
	Overridden            int `json:"overridden"`
	Blocked               int `json:"blocked"`
	NoIdentity            int `json:"no_identity"`
	SyntheticTelegramRows int `json:"synthetic_telegram_rows"`
	EmailTaken            int `json:"email_taken"`
	PhoneTaken            int `json:"phone_taken"`
	ProviderAlreadyLinked int `json:"provider_already_linked"`
	OverrideUserMissing   int `json:"override_user_missing"`
}

// Report lists only the users that need attention: every plan that is not a
// clean no-op.
type Report struct {
	DryRun      bool       `json:"dry_run"`
	GeneratedAt time.Time  `json:"generated_at"`
	Summary     Summary    `json:"summary"`
	Users       []UserPlan `json:"users"`
}

func buildReport(generatedAt time.Time, plans []UserPlan) *Report {
	r := &Report{DryRun: true, GeneratedAt: generatedAt, Users: []UserPlan{}}
	s := &r.Summary
	s.Users = len(plans)
	actions := map[Action]*int{
		ActionNoop: &s.Noop, ActionCreate: &s.Create, ActionLink: &s.Link, ActionSplit: &s.SplitIdentity,
		ActionOverridden: &s.Overridden, ActionBlocked: &s.Blocked, ActionNoIdentity: &s.NoIdentity,
	}
	flags := map[string]*int{
		FlagSyntheticTelegramRow: &s.SyntheticTelegramRows, FlagEmailTaken: &s.EmailTaken, FlagPhoneTaken: &s.PhoneTaken,
		FlagProviderAlreadyLinked: &s.ProviderAlreadyLinked, FlagOverrideUserMissing: &s.OverrideUserMissing,
	}
	for _, p := range plans {
		*actions[p.Action]++
		for _, f := range p.Flags {
			*flags[f]++
		}
		if p.Action != ActionNoop || len(p.Flags) > 0 {
			r.Users = append(r.Users, p)
		}
	}
	return r
}
