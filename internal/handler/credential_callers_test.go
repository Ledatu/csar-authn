package handler

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
)

func TestCredentialPurposeRequiresOwnerChoiceForAgent(t *testing.T) {
	owner := uuid.New()
	first, err := (credentialCallerInput{}).newCaller(owner, "An agent product name")
	if err != nil || first.Kind != caller.Application {
		t.Fatal("a product label inferred agent execution", err)
	}
	second, err := (credentialCallerInput{CallerKind: caller.Agent, CallerLabel: "My analysis agent"}).newCaller(owner, "")
	if err != nil || second.Kind != caller.Agent || second.OwnerID != owner || second.ID == first.ID {
		t.Fatal("explicit owner purpose was not registered", err)
	}
	id := uuid.New()
	if created, err := (credentialCallerInput{CallerID: &id}).newCaller(owner, "unused"); err != nil || created != nil {
		t.Fatal("explicit reuse created another caller", err)
	}
	for _, input := range []credentialCallerInput{{CallerID: &id, CallerKind: caller.Agent}, {CallerKind: caller.Human}, {CallerKind: caller.Service}, {CallerLabel: "bad\nlabel"}} {
		if _, err := input.newCaller(owner, "label"); err == nil {
			t.Fatal("untrusted or ambiguous caller authority accepted")
		}
	}
}
