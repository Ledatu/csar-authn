// Package legacysync plans legacy Mongo user identities into authn users and
// provider links. Mongo email and phone are only compared, never copied: an
// unverified address in authn would let its owner take the account over.
package legacysync

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidRequest = errors.New("invalid legacy users sync request")

// Request is the users part of the legacy snapshot pushed by the aurum exporter.
type Request struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Users       []LegacyUser `json:"users"`
}

// LegacyUser is a Mongo usertelegrams row. Telegram users are keyed by their
// Telegram id; Yandex-only users by a synthetic id and carry no telegram_id.
type LegacyUser struct {
	LegacyID   int64  `json:"legacy_id"`
	TelegramID string `json:"telegram_id,omitempty"`
	YandexID   string `json:"yandex_id,omitempty"`
	FirstName  string `json:"first_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
	Username   string `json:"username,omitempty"`
	PhotoURL   string `json:"photo_url,omitempty"`
	Email      string `json:"email,omitempty"`
	Phone      string `json:"phone,omitempty"`
}

func (r *Request) Validate(now time.Time, maxUsers int) error {
	if r.GeneratedAt.IsZero() {
		return fmt.Errorf("%w: generated_at is required", ErrInvalidRequest)
	}
	if r.GeneratedAt.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("%w: generated_at is in the future", ErrInvalidRequest)
	}
	if len(r.Users) == 0 {
		return fmt.Errorf("%w: users must not be empty", ErrInvalidRequest)
	}
	if len(r.Users) > maxUsers {
		return fmt.Errorf("%w: at most %d users per request", ErrInvalidRequest, maxUsers)
	}
	seen := make(map[int64]struct{}, len(r.Users))
	for _, u := range r.Users {
		if u.LegacyID <= 0 {
			return fmt.Errorf("%w: legacy_id must be positive", ErrInvalidRequest)
		}
		if _, dup := seen[u.LegacyID]; dup {
			return fmt.Errorf("%w: legacy_id %d is repeated", ErrInvalidRequest, u.LegacyID)
		}
		seen[u.LegacyID] = struct{}{}
	}
	return nil
}
