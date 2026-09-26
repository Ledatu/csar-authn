package legacysync

import (
	"context"
	"errors"
	"fmt"
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
}

type Options struct {
	MaxUsers  int
	Overrides map[int64]string
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
	return buildReport(req.GeneratedAt, plans), nil
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
