package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
)

func TestCallerRegistrationKeepsIssuerOwnedKindsSeparate(t *testing.T) {
	for _, kind := range []caller.Kind{caller.Human, caller.Service, caller.Unknown, "robot", caller.Agent, caller.Application} {
		c := &Caller{ID: uuid.New(), OwnerID: uuid.New(), Kind: kind, Label: "  worker  "}
		err := c.ValidateRegistration()
		allowed := kind == caller.Agent || kind == caller.Application
		if (err == nil) != allowed {
			t.Fatalf("unexpected registration policy for %s: %v", kind, err)
		}
		if allowed && c.Label != "worker" {
			t.Fatal("label was not normalized")
		}
		body, err := json.Marshal(c)
		if err != nil || strings.Contains(string(body), c.OwnerID.String()) {
			t.Fatal("caller response exposes owner", err)
		}
	}
}
