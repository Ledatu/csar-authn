package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/identityimport"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/gatewayctx"
)

func importContext() context.Context {
	return gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Subject: "svc:fixture-import", RequestID: "import-fixture"})
}
func importMutation(record identityimport.Record, plan identityimport.Plan) identityimport.Mutation {
	return identityimport.Mutation{Record: record, Expected: plan, Actor: "svc:fixture-import", Importer: "fixture", Source: "unrelated-source"}
}
func TestIdentityImportAtomicLifecyclePG(t *testing.T) {
	s := auditFixture(t)
	ctx := importContext()
	a := identityimport.Identity{Provider: "unrelated-a", ID: "opaque-user-one"}
	b := identityimport.Identity{Provider: "unrelated-b", ID: "opaque-user-two"}
	record := identityimport.Record{Key: "record-key", DisplayName: "Fixture name", Email: "unverified@example.test", Phone: "+79990002211", Identities: []identityimport.Link{{Identity: a}, {Identity: b}}}
	state, err := s.ReadIdentityImportState(ctx, record, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	planned := identityimport.Decide(record, uuid.Nil, state)
	if planned.Action != "create" {
		t.Fatal(planned)
	}
	result, err := s.ApplyIdentityImport(ctx, importMutation(record, planned))
	if err != nil || result.Applied != "ok" {
		t.Fatal(result, err)
	}
	user, err := s.GetUserByID(ctx, result.UserID)
	if err != nil || user.Email != "" || user.Phone != "" || user.DisplayName != "Fixture name" {
		t.Fatal("contact authority adopted", user, err)
	}
	accounts, err := s.GetOAuthAccountsByUserID(ctx, user.ID)
	if err != nil || len(accounts) != 2 {
		t.Fatal(accounts, err)
	}
	for _, a := range accounts {
		if a.EmailVerified || a.Email != "" || a.AccessToken != "" || a.RefreshToken != "" {
			t.Fatal("import created login/token authority", a)
		}
	}
	var audits int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM csar_audit_outbox`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal(audits, err)
	}
	record.Identities = append(record.Identities, identityimport.Link{Identity: identityimport.Identity{Provider: "unrelated-c", ID: "third"}})
	state, err = s.ReadIdentityImportState(ctx, record, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	planned = identityimport.Decide(record, uuid.Nil, state)
	if planned.Action != "link" {
		t.Fatal(planned)
	}
	if _, err := s.pool.Exec(ctx, `DROP TABLE csar_audit_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyIdentityImport(ctx, importMutation(record, planned)); err == nil {
		t.Fatal("unaudited link committed")
	}
	if _, err := s.GetOAuthAccount(ctx, "unrelated-c", "third"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("link survived audit rollback", err)
	}
	// Audit failure also rolls back a newly created user and every link.
	fresh := identityimport.Record{Key: "fresh", Identities: []identityimport.Link{{Identity: identityimport.Identity{Provider: "unrelated-z", ID: "fresh"}}}}
	if _, err := s.ApplyIdentityImport(ctx, importMutation(fresh, identityimport.Plan{Key: "fresh", Action: "create"})); err == nil {
		t.Fatal("unaudited create committed")
	}
	var users int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil || users != 1 {
		t.Fatal("create survived rollback", users, err)
	}
}

func TestIdentityImportCollisionsAndConcurrencyPG(t *testing.T) {
	s := auditFixture(t)
	ctx := importContext()
	existing, err := s.CreateUser(ctx, &store.User{DisplayName: "Existing"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthAccount(ctx, &store.OAuthAccount{UserID: existing.ID, Provider: "email", ProviderUserID: "occupied@example.test", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	record := identityimport.Record{Key: "new", Email: "Occupied@Example.Test", Identities: []identityimport.Link{{Identity: identityimport.Identity{Provider: "external", ID: "new"}}}}
	st, err := s.ReadIdentityImportState(ctx, record, uuid.Nil)
	if err != nil || identityimport.Decide(record, uuid.Nil, st).Action != "blocked" {
		t.Fatal("email provider collision missed", st, err)
	}
	record.Email = ""
	record.Conflicts = []identityimport.Identity{{Provider: "email", ID: "occupied@example.test"}}
	st, err = s.ReadIdentityImportState(ctx, record, uuid.Nil)
	if err != nil || !st.ForbiddenMatch {
		t.Fatal(st, err)
	}
	record.Conflicts = nil
	// Independent concurrent attempts cannot create duplicate users/ownership.
	var wg sync.WaitGroup
	results := make(chan identityimport.Plan, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			p, err := s.ApplyIdentityImport(ctx, importMutation(record, identityimport.Plan{Key: record.Key, Action: "create"}))
			results <- p
			errs <- err
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	applied := 0
	for p := range results {
		if p.Applied == "ok" {
			applied++
		}
	}
	if applied != 1 {
		t.Fatal("concurrent import applied twice", applied)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_accounts WHERE provider='external'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var leaked bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM csar_audit_outbox WHERE convert_from(payload,'UTF8') LIKE $1)`, "%"+strings.ToLower("occupied@example.test")+"%").Scan(&leaked); err != nil || leaked {
		t.Fatal("audit leaked contacts", err)
	}
}

func TestIdentityImportSharesLegacyLockPG(t *testing.T) {
	s := auditFixture(t)
	s.legacySyncConnConfig = s.pool.Config().ConnConfig.Copy()
	release, ok, err := s.TryLegacyUsersSyncLock(context.Background())
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	defer release()
	if _, ok, err := s.TryIdentityImportLock(context.Background()); err != nil || ok {
		t.Fatal("new importer bypassed legacy lock", ok, err)
	}
}
