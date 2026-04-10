package store

import (
	"time"

	"github.com/google/uuid"
)

// AttributionTouch is generic first-party attribution state associated with a user.
type AttributionTouch struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	SourceType     string
	SourceKey      string
	SourceMetadata map[string]string
	TouchedAt      time.Time
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
	ReplacedBy     *uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func CloneAttributionMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func SameAttributionTouchSource(a, b *AttributionTouch) bool {
	if a == nil || b == nil {
		return false
	}
	if a.SourceType != b.SourceType || a.SourceKey != b.SourceKey {
		return false
	}
	if len(a.SourceMetadata) != len(b.SourceMetadata) {
		return false
	}
	for key, value := range a.SourceMetadata {
		if b.SourceMetadata[key] != value {
			return false
		}
	}
	return true
}
