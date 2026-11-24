package handler

import (
	"errors"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/caller"
)

// Credential purpose is chosen by the owner. An omitted purpose registers a
// generic application; protocol names and User-Agent never establish an agent.
type credentialCallerInput struct {
	CallerID    *uuid.UUID  `json:"caller_id"`
	CallerKind  caller.Kind `json:"caller_kind"`
	CallerLabel string      `json:"caller_label"`
}

func (in credentialCallerInput) newCaller(owner uuid.UUID, defaultLabel string) (*store.Caller, error) {
	if in.CallerID != nil {
		if *in.CallerID == uuid.Nil || in.CallerKind != "" || in.CallerLabel != "" {
			return nil, errors.New("choose an existing caller or a new caller, not both")
		}
		return nil, nil
	}
	kind, label := in.CallerKind, in.CallerLabel
	if kind == "" {
		kind = caller.Application
	}
	if label == "" {
		label = defaultLabel
	}
	if label == "" {
		label = "Приложение"
	}
	c := &store.Caller{ID: uuid.New(), OwnerID: owner, Kind: kind, Label: label}
	if err := c.ValidateRegistration(); err != nil {
		return nil, err
	}
	return c, nil
}
