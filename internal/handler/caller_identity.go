package handler

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

var errCallerRevoked = errors.New("registered caller revoked")

func (h *Handler) credentialIdentity(ctx context.Context, owner uuid.UUID, kind caller.CredentialKind, reference string) (*caller.Identity, error) {
	id := &caller.Identity{Version: caller.Version, CallerKind: caller.Unknown, OwnerSubject: owner.String(), EffectiveSubject: owner.String(),
		CredentialKind: kind, CredentialID: reference, Assurance: caller.Legacy}
	registry, ok := h.store.(store.CallerCredentialStore)
	if !ok {
		return id, nil
	}
	c, err := registry.CallerForCredential(ctx, owner, kind, reference)
	if errors.Is(err, store.ErrNotFound) {
		return id, nil
	}
	if err != nil {
		return nil, err
	}
	if c == nil || c.OwnerID != owner || c.ID == uuid.Nil || c.Kind != caller.Agent && c.Kind != caller.Application {
		return nil, store.ErrCallerBinding
	}
	if c.RevokedAt != nil {
		return nil, errCallerRevoked
	}
	id.CallerKind, id.CallerID, id.Assurance = c.Kind, c.ID.String(), caller.Verified
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}

func sessionIdentity(sess *store.Session, user *store.User) *caller.Identity {
	owner := sess.UserID
	if sess.ImpersonatorUserID != nil {
		owner = *sess.ImpersonatorUserID
	}
	// Session.ID is the bearer cookie itself, so it must never become an audit
	// credential reference. Leave that reference absent until separately issued.
	return &caller.Identity{Version: caller.Version, CallerKind: caller.Human, CallerID: owner.String(), OwnerSubject: owner.String(),
		EffectiveSubject: user.ID.String(), CredentialKind: caller.Session, Assurance: caller.Verified}
}
