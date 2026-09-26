package mock

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

func (s *Store) TryLegacyUsersSyncLock(_ context.Context) (func(), bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.legacyUsersSyncLocked {
		return nil, false, nil
	}
	s.legacyUsersSyncLocked = true
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.legacyUsersSyncLocked = false
	}, true, nil
}

func (s *Store) LinkLegacyAccount(ctx context.Context, acct *store.OAuthAccount) error {
	return s.CreateOAuthAccount(ctx, acct)
}

func (s *Store) CreateLegacyUser(_ context.Context, u *store.User, accounts []store.OAuthAccount) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range accounts {
		if _, ok := s.accounts[oauthKey(a.Provider, a.ProviderUserID)]; ok {
			return nil, store.ErrProviderAlreadyLinked
		}
	}
	created := *u
	created.ID = uuid.New()
	now := time.Now()
	created.CreatedAt, created.UpdatedAt = now, now
	s.users[created.ID] = &created
	for _, a := range accounts {
		a.UserID = created.ID
		a.LinkedAt, a.UpdatedAt = now, now
		s.accounts[oauthKey(a.Provider, a.ProviderUserID)] = &a
	}
	out := created
	return &out, nil
}
