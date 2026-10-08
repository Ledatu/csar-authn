package postgres

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/gatewayctx"
)

// This fixture never uses CSAR_TEST_DSN; existing application databases are forbidden.
func auditFixture(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated localhost audit database not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || cfg.ConnConfig.Database != "csar_audit_test" || len(cfg.ConnConfig.Fallbacks) > 0 {
		t.Fatal("only isolated localhost csar_audit_test accepted")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
	if err != nil {
		t.Fatal(err)
	}
	schema := "producer_test_" + uuid.NewString()[:8]
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = ident
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	s := &Store{pool: pool, logger: slog.Default()}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnableAuditOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
func actorContext() context.Context {
	return gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Subject: "verified-user", RequestID: "test-request"})
}

func TestAuthnOutboxAtomicAccountsAndKeys(t *testing.T) {
	s := auditFixture(t)
	ctx := actorContext()
	sa := &store.ServiceAccount{Name: "audit-test-service", PublicKeyPEM: "public-key-one", AllowedAudiences: []string{"test"}, TokenTTL: time.Hour}
	if _, err := s.CreateOrReactivateServiceAccount(ctx, sa); err != nil {
		t.Fatal(err)
	}
	sa, err := s.UpdateServiceAccountPolicy(ctx, sa.Name, []string{"new"}, false, 30*time.Minute, sa.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateServiceAccountKey(ctx, sa.Name, "public-key-two"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeServiceAccount(ctx, sa.Name); err != nil {
		t.Fatal(err)
	}
	sa.PublicKeyPEM = "public-key-three"
	if reactivated, err := s.CreateOrReactivateServiceAccount(ctx, sa); err != nil || !reactivated {
		t.Fatal("reactivation failed", err)
	}
	user, err := s.CreateUser(ctx, &store.User{DisplayName: "audit test"})
	if err != nil {
		t.Fatal(err)
	}
	key := &store.APICredential{ID: uuid.New(), OwnerID: user.ID, SellerID: "seller", Label: "test", TokenHash: strings.Repeat("a", 64), Prefix: "test-only-secret-prefix", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateAPICredential(ctx, key, 5); err != nil {
		t.Fatal(err)
	}
	backlog, err := s.outbox.Backlog(ctx)
	if err != nil || backlog.Count != 6 {
		t.Fatalf("missing account/key events: %+v %v", backlog, err)
	}
	var leaked bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM csar_audit_outbox WHERE convert_from(payload,'UTF8') LIKE '%test-only-secret-prefix%' OR convert_from(payload,'UTF8') LIKE '%public-key-one%' OR convert_from(payload,'UTF8') LIKE $1)`, "%"+key.TokenHash+"%").Scan(&leaked); err != nil || leaked {
		t.Fatal("audit payload leaked credential material", err)
	}
	if _, err := s.pool.Exec(ctx, `DROP TABLE csar_audit_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAPICredential(ctx, user.ID, key.ID); err == nil {
		t.Fatal("key revoked without an audit event")
	}
	var revoked *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT revoked_at FROM seller_api_credentials WHERE id=$1`, key.ID).Scan(&revoked); err != nil || revoked != nil {
		t.Fatal("key revoke survived enqueue failure", err)
	}
	revision := sa.Revision
	if _, err := s.UpdateServiceAccountPolicy(ctx, sa.Name, []string{"lost"}, false, time.Hour, revision); err == nil {
		t.Fatal("policy changed without event")
	}
	current, err := s.GetServiceAccount(ctx, sa.Name)
	if err != nil || current.Revision != revision {
		t.Fatal("policy survived enqueue failure", err)
	}
	if s.TransactionalAudit("session.revoke") {
		t.Fatal("unconverted actions incorrectly declared transactional")
	}
}
