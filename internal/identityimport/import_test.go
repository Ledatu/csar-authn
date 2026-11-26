package identityimport

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/authnconfig"
)

func TestDecideNeverMergesOrAdoptsContactAuthority(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	first := Identity{Provider: "provider-a", ID: "opaque:one"}
	second := Identity{Provider: "provider-b", ID: "external-two"}
	r := Record{Key: "source-key", Identities: []Link{{Identity: first}, {Identity: second}}}
	for _, tc := range []struct {
		name     string
		state    State
		override uuid.UUID
		action   string
	}{
		{name: "create", state: State{}, action: "create"},
		{name: "one matched", state: State{Matches: map[Identity]uuid.UUID{first: a}, Target: a, TargetExists: true}, action: "link"},
		{name: "same user", state: State{Matches: map[Identity]uuid.UUID{first: a, second: a}, Target: a, TargetExists: true}, action: "noop"},
		{name: "split", state: State{Matches: map[Identity]uuid.UUID{first: a, second: b}}, action: "split_identity"},
		{name: "contact", state: State{ContactConflict: true}, action: "blocked"},
		{name: "source ambiguity", state: State{ForbiddenMatch: true}, action: "blocked"},
		{name: "missing override", override: a, action: "blocked"},
		{name: "configured override", override: a, state: State{Target: a, TargetExists: true}, action: "overridden"},
		{name: "override cannot steal", override: b, state: State{Matches: map[Identity]uuid.UUID{first: a}, Target: b, TargetExists: true}, action: "split_identity"},
		{name: "second same provider", state: State{Matches: map[Identity]uuid.UUID{first: a}, Target: a, TargetExists: true, ExistingProviders: map[string]string{"provider-b": "different"}}, action: "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(r, tc.override, tc.state)
			if got.Action != tc.action {
				t.Fatal(got)
			}
		})
	}
}

type fakeStore struct {
	writes int
	locked bool
	state  State
}

func (s *fakeStore) ReadIdentityImportState(context.Context, Record, uuid.UUID) (State, error) {
	return s.state, nil
}
func (s *fakeStore) TryIdentityImportLock(context.Context) (func(), bool, error) {
	s.locked = true
	return func() { s.locked = false }, true, nil
}
func (s *fakeStore) ApplyIdentityImport(_ context.Context, m Mutation) (Plan, error) {
	s.writes++
	p := m.Expected
	p.Applied = "ok"
	return p, nil
}

func TestRunBoundsAndIndependentImporter(t *testing.T) {
	p := authnconfig.IdentityImporter{Subject: "svc:second-importer", Source: "unrelated-app", Providers: []string{"unrelated-idp"}, MaxUsers: 2, Apply: authnconfig.IdentityImportApply{Enabled: true, Actions: []string{"create"}, MaxCreates: 1}}
	r := Request{Version: 1, Importer: "second", Source: p.Source, GeneratedAt: time.Now(), Records: []Record{{Key: "not-a-number", Identities: []Link{{Identity: Identity{Provider: "unrelated-idp", ID: "opaque-value"}}}}}}
	st := &fakeStore{}
	out, err := Run(context.Background(), st, &r, p, p.Subject, false, nil)
	if err != nil || !out.DryRun || st.writes != 0 {
		t.Fatal(out, err)
	}
	if _, err := Run(context.Background(), st, &r, p, "svc:foreign", true, []string{"create"}); err == nil {
		t.Fatal("foreign actor imported")
	}
	if _, err := Run(context.Background(), st, &r, p, p.Subject, true, []string{"link"}); err == nil {
		t.Fatal("unapproved action imported")
	}
	r.Records = append(r.Records, Record{Key: "another", Identities: []Link{{Identity: Identity{Provider: "unrelated-idp", ID: "another-value"}}}})
	out, err = Run(context.Background(), st, &r, p, p.Subject, true, []string{"create"})
	if err != nil || len(out.Refused) != 1 || st.writes != 0 || st.locked {
		t.Fatal("whole-action cap was not enforced", out, err)
	}
	r.Records[1].Identities[0].ID = "opaque-value"
	if err := r.Validate(p, time.Now()); err == nil {
		t.Fatal("duplicate source identities accepted")
	}
	r.Records = r.Records[:1]
	r.Records[0].Identities[0].Provider = "email"
	if err := r.Validate(p, time.Now()); err == nil {
		t.Fatal("contact login authority imported")
	}
}
