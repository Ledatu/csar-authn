package legacysync

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

type Store interface {
	GetUsersByProviderIDs(ctx context.Context, provider string, providerUserIDs []string) ([]store.ProviderUser, error)
	GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]store.ResolvedUser, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID uuid.UUID) ([]store.OAuthAccount, error)
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*store.User, error)
	TryLegacyUsersSyncLock(ctx context.Context) (release func(), ok bool, err error)
	LinkLegacyAccount(ctx context.Context, acct *store.OAuthAccount) error
	CreateLegacyUser(ctx context.Context, u *store.User, accounts []store.OAuthAccount) (*store.User, error)
}

var ErrRunInProgress = errors.New("a legacy users sync apply run is already in progress")

type Options struct {
	MaxUsers  int
	Overrides map[int64]string
}

// ApplyOptions lists the actions a run may write and their per-run caps.
type ApplyOptions struct {
	Actions    []Action
	MaxLinks   int
	MaxCreates int
}

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(st Store) *Service {
	return &Service{store: st, now: time.Now}
}

// DryRun plans every legacy user without writing anything.
func (s *Service) DryRun(ctx context.Context, req *Request, opts Options) (*Report, error) {
	plans, err := s.plan(ctx, req, opts)
	if err != nil {
		return nil, err
	}
	return buildReport(req.GeneratedAt, plans), nil
}

// Apply re-plans against fresh authn state and writes the planned links and
// users of the allowed actions. An action whose planned count exceeds its cap
// is refused whole. Writes never touch email, phone, sessions or merges.
func (s *Service) Apply(ctx context.Context, req *Request, opts Options, apply ApplyOptions) (*Report, error) {
	if err := req.Validate(s.now(), opts.MaxUsers); err != nil {
		return nil, err
	}
	release, ok, err := s.store.TryLegacyUsersSyncLock(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRunInProgress
	}
	defer release()

	plans, err := s.plan(ctx, req, opts)
	if err != nil {
		return nil, err
	}
	active, refused := activeActions(plans, apply)

	users := make(map[int64]LegacyUser, len(req.Users))
	for _, u := range req.Users {
		users[u.LegacyID] = u
	}
	applied := &ApplySummary{}
	for i := range plans {
		p := &plans[i]
		if !active[p.Action] {
			continue
		}
		s.applyUser(ctx, users[p.LegacyID], p)
		applied.count(p)
	}

	r := buildReport(req.GeneratedAt, plans)
	r.DryRun = false
	r.Applied = applied
	r.Refused = refused
	return r, nil
}

func (s *Service) plan(ctx context.Context, req *Request, opts Options) ([]UserPlan, error) {
	if err := req.Validate(s.now(), opts.MaxUsers); err != nil {
		return nil, err
	}
	st, err := s.loadState(ctx, req.Users, opts.Overrides)
	if err != nil {
		return nil, err
	}

	plans := make([]UserPlan, 0, len(req.Users))
	for _, u := range req.Users {
		p := resolveUser(u, st)
		switch p.Action {
		case ActionLink:
			err = s.checkLinkTarget(ctx, &p)
		case ActionCreate:
			err = s.checkContactCollisions(ctx, u, &p)
		}
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}

func activeActions(plans []UserPlan, apply ApplyOptions) (map[Action]bool, []Refusal) {
	planned := map[Action]int{}
	for _, p := range plans {
		planned[p.Action]++
	}
	caps := map[Action]int{ActionLink: apply.MaxLinks, ActionCreate: apply.MaxCreates}
	active := map[Action]bool{}
	var refused []Refusal
	for _, a := range apply.Actions {
		limit, known := caps[a]
		switch {
		case !known:
			continue
		case planned[a] > limit:
			refused = append(refused, Refusal{Action: a, Planned: planned[a], Cap: limit})
		default:
			active[a] = true
		}
	}
	return active, refused
}

func (s *Service) applyUser(ctx context.Context, u LegacyUser, p *UserPlan) {
	var err error
	switch p.Action {
	case ActionLink:
		var userID uuid.UUID
		if userID, err = uuid.Parse(p.UserID); err == nil {
			acct := legacyAccount(u, p.AddLinks[0])
			acct.UserID = userID
			err = s.store.LinkLegacyAccount(ctx, &acct)
		}
	case ActionCreate:
		accounts := make([]store.OAuthAccount, 0, len(p.AddLinks))
		for _, provider := range p.AddLinks {
			accounts = append(accounts, legacyAccount(u, provider))
		}
		var created *store.User
		if created, err = s.store.CreateLegacyUser(ctx, legacyProfile(u), accounts); err == nil {
			p.UserID = created.ID.String()
		}
	}
	switch {
	case errors.Is(err, store.ErrProviderAlreadyLinked):
		p.Applied, p.Error = AppliedFailed, "provider link was taken since the plan"
	case err != nil:
		p.Applied, p.Error = AppliedFailed, "write failed"
	default:
		p.Applied = AppliedOK
	}
}

// legacyAccount builds a link the way a first login would, minus tokens and
// email: the sync never vouches for an address.
func legacyAccount(u LegacyUser, provider string) store.OAuthAccount {
	acct := store.OAuthAccount{
		Provider:         provider,
		ProviderMetadata: map[string]interface{}{"linked_by": "legacy_sync"},
	}
	switch provider {
	case ProviderTelegram:
		acct.ProviderUserID = u.TelegramID
		if u.Username != "" {
			acct.ProviderMetadata["legacy_username"] = u.Username
		}
	case ProviderYandex:
		acct.ProviderUserID = u.YandexID
	}
	return acct
}

func legacyProfile(u LegacyUser) *store.User {
	name := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
	if name == "" && u.Username != "" {
		name = "@" + strings.TrimPrefix(u.Username, "@")
	}
	return &store.User{DisplayName: name, AvatarURL: safeAvatarURL(u.PhotoURL)}
}

func safeAvatarURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || len(raw) > 2048 {
		return ""
	}
	return parsed.String()
}

func (s *Service) loadState(ctx context.Context, users []LegacyUser, overrides map[int64]string) (State, error) {
	var telegramIDs, yandexIDs []string
	for _, u := range users {
		if u.TelegramID != "" {
			telegramIDs = append(telegramIDs, u.TelegramID)
		} else {
			telegramIDs = append(telegramIDs, syntheticTelegramID(u.LegacyID))
		}
		if u.YandexID != "" {
			yandexIDs = append(yandexIDs, u.YandexID)
		}
	}

	st := State{Overrides: map[int64]uuid.UUID{}, MissingOverrides: map[int64]struct{}{}}
	var err error
	if st.Telegram, err = s.providerLinks(ctx, ProviderTelegram, telegramIDs); err != nil {
		return State{}, err
	}
	if st.Yandex, err = s.providerLinks(ctx, ProviderYandex, yandexIDs); err != nil {
		return State{}, err
	}
	if err := s.loadOverrides(ctx, overrides, &st); err != nil {
		return State{}, err
	}
	return st, nil
}

func (s *Service) providerLinks(ctx context.Context, provider string, ids []string) (map[string]uuid.UUID, error) {
	links := make(map[string]uuid.UUID, len(ids))
	if len(ids) == 0 {
		return links, nil
	}
	users, err := s.store.GetUsersByProviderIDs(ctx, provider, ids)
	if err != nil {
		return nil, fmt.Errorf("resolving %s links: %w", provider, err)
	}
	for _, u := range users {
		links[u.ProviderUserID] = u.ID
	}
	return links, nil
}

func (s *Service) loadOverrides(ctx context.Context, overrides map[int64]string, st *State) error {
	if len(overrides) == 0 {
		return nil
	}
	legacyIDsByUser := make(map[uuid.UUID][]int64, len(overrides))
	ids := make([]uuid.UUID, 0, len(overrides))
	for legacyID, raw := range overrides {
		id, err := uuid.Parse(raw)
		if err != nil {
			return fmt.Errorf("identity override %d: %w", legacyID, err)
		}
		if _, seen := legacyIDsByUser[id]; !seen {
			ids = append(ids, id)
		}
		legacyIDsByUser[id] = append(legacyIDsByUser[id], legacyID)
		st.MissingOverrides[legacyID] = struct{}{}
	}
	resolved, err := s.store.GetUsersByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("resolving identity overrides: %w", err)
	}
	for _, u := range resolved {
		for _, legacyID := range legacyIDsByUser[u.RequestedID] {
			st.Overrides[legacyID] = u.ID
			delete(st.MissingOverrides, legacyID)
		}
	}
	return nil
}

// checkLinkTarget blocks a link that would give a user a second account of
// the same provider; which of the two is right is a human decision.
func (s *Service) checkLinkTarget(ctx context.Context, p *UserPlan) error {
	userID, err := uuid.Parse(p.UserID)
	if err != nil {
		return fmt.Errorf("link target %q: %w", p.UserID, err)
	}
	accounts, err := s.store.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("loading links of %s: %w", userID, err)
	}
	for _, a := range accounts {
		if a.Provider == p.AddLinks[0] {
			p.AddLinks = nil
			p.block(FlagProviderAlreadyLinked)
			return nil
		}
	}
	return nil
}

// checkContactCollisions blocks creating a second account for someone who
// probably already has one: a real login would have linked them by phone or
// verified email, which the sync cannot verify.
func (s *Service) checkContactCollisions(ctx context.Context, u LegacyUser, p *UserPlan) error {
	if email, err := store.NormalizeEmailString(u.Email); u.Email != "" && err == nil {
		other, err := s.store.GetUserByEmail(ctx, email)
		switch {
		case err == nil:
			p.EmailTakenBy = other.ID.String()
			p.block(FlagEmailTaken)
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("checking legacy email: %w", err)
		}
	}
	for _, phone := range phoneVariants(u.Phone) {
		other, err := s.store.GetUserByPhone(ctx, phone)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("checking legacy phone: %w", err)
		}
		p.PhoneTakenBy = other.ID.String()
		p.block(FlagPhoneTaken)
		break
	}
	if p.Action == ActionBlocked {
		p.AddLinks = nil
	}
	return nil
}

// phoneVariants covers both forms providers hand authn: "+79..." and "79...".
func phoneVariants(raw string) []string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, raw)
	if len(digits) < 10 {
		return nil
	}
	return []string{"+" + digits, digits}
}
