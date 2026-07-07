package store

import (
	"context"

	"github.com/google/uuid"
)

// ResolveMergeDirection picks the canonical merge target (older account) and
// source (newer account). Tie-breaks equal created_at with UUID ordering.
func ResolveMergeDirection(a, b *User) (targetID, sourceID uuid.UUID, err error) {
	if a == nil || b == nil {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}
	if a.ID == b.ID {
		return uuid.Nil, uuid.Nil, ErrSelfMerge
	}
	if a.MergedInto != nil || b.MergedInto != nil {
		return uuid.Nil, uuid.Nil, ErrUserAlreadyMerged
	}

	older, newer := a, b
	if a.CreatedAt.After(b.CreatedAt) {
		older, newer = b, a
	} else if a.CreatedAt.Equal(b.CreatedAt) && a.ID.String() > b.ID.String() {
		older, newer = b, a
	}

	return older.ID, newer.ID, nil
}

// ResolveMergeDirectionByID loads both users and returns canonical merge direction.
func ResolveMergeDirectionByID(ctx context.Context, st Store, idA, idB uuid.UUID) (targetID, sourceID uuid.UUID, err error) {
	userA, err := st.GetUserByID(ctx, idA)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	userB, err := st.GetUserByID(ctx, idB)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return ResolveMergeDirection(userA, userB)
}
