package postgres

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only synthetic local fixtures are accepted; no migrations or business writes.
func odysseyFixture(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("ODYSSEY_TEST_SESSION_DSN")
	if dsn == "" {
		t.Skip("isolated Odyssey fixture not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid fixture DSN")
	}
	if cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Database != "csar_authn_session" || len(cfg.ConnConfig.Fallbacks) != 0 {
		t.Fatal("only isolated localhost csar_authn_session accepted")
	}
	return &Store{legacySyncConnConfig: cfg.ConnConfig.Copy(), logger: slog.Default()}, dsn
}

func eventuallyLegacyLock(t *testing.T, s *Store) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		release, ok, err := s.TryLegacyUsersSyncLock(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return release
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("lock was not released")
	return nil
}

func TestLegacySyncLockRejectsMissingSessionDSN(t *testing.T) {
	if _, ok, err := (&Store{}).TryLegacyUsersSyncLock(context.Background()); err == nil || ok {
		t.Fatal("missing session endpoint must fail closed")
	}
}

func TestLegacySyncLockInvalidDSNIsRedacted(t *testing.T) {
	_, err := New(context.Background(), "unused", WithLegacyUsersSyncDSN("postgres://user:SECRET@localhost:bad/db"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("invalid lock DSN must be rejected without exposing it")
	}
}

func TestOdysseyLegacyLockExclusionAndCancellation(t *testing.T) {
	s, _ := odysseyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	release, ok, err := s.TryLegacyUsersSyncLock(ctx)
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	t.Cleanup(release)
	peer := &Store{legacySyncConnConfig: s.legacySyncConnConfig.Copy(), logger: slog.Default()}
	if peerDSN := os.Getenv("ODYSSEY_TEST_PEER_SESSION_DSN"); peerDSN != "" {
		// Reuse the same safety guard for a different local pooler.
		t.Setenv("ODYSSEY_TEST_SESSION_DSN", peerDSN)
		peer, _ = odysseyFixture(t)
	}
	secondRelease, secondOK, secondErr := peer.TryLegacyUsersSyncLock(context.Background())
	if secondRelease != nil {
		secondRelease()
	}
	if secondErr != nil || secondOK {
		t.Fatalf("concurrent replica: ok=%v err=%v", secondOK, secondErr)
	}
	cancel()
	release()
	release() // Idempotence must not affect another client's ownership.
	next := eventuallyLegacyLock(t, peer)
	next()
}

func TestOdysseyLegacyLockAbruptDisconnectResetsBackend(t *testing.T) {
	s, dsn := odysseyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", legacyUsersSyncLockKey).Scan(&ok); err != nil || !ok {
		t.Fatalf("raw lock: ok=%v err=%v", ok, err)
	}
	// No PostgreSQL Terminate and no explicit advisory unlock.
	if err := conn.PgConn().Conn().Close(); err != nil {
		t.Fatal(err)
	}
	// Check all sessions before trying again: reentrant acquisition on a dirty
	// reused backend alone could otherwise hide a leaked lock.
	observer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(ctx) }()
	for {
		var count int
		err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory'
		 AND classid=$1 AND objid=$2 AND objsubid=1`, legacyUsersSyncLockKey>>32, legacyUsersSyncLockKey&0xffffffff).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("abrupt client disconnect leaked the advisory lock")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := observer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	release := eventuallyLegacyLock(t, s)
	release()
}

func TestOdysseyLegacyLockIndependentFromBusinessPool(t *testing.T) {
	_, sessionDSN := odysseyFixture(t)
	u, err := url.Parse(sessionDSN)
	if err != nil {
		t.Fatal("invalid fixture URL")
	}
	u.Path = "/csar_authn"
	query := u.Query()
	query.Set("pool_max_conns", "1")
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := New(ctx, u.String(), WithLegacyUsersSyncDSN(sessionDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	busy, err := s.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Release()
	release, ok, err := s.TryLegacyUsersSyncLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock must not borrow the occupied business pool: ok=%v err=%v", ok, err)
	}
	release()
}

func TestOdysseySessionBudgetSaturationIsBounded(t *testing.T) {
	s, dsn := odysseyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 { // Fixture and production session routes are limited to two.
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	release, ok, err := s.TryLegacyUsersSyncLock(ctx)
	if release != nil {
		release()
	}
	if err == nil || ok || time.Since(started) > 6*time.Second {
		t.Fatalf("saturated route must fail within its bound: ok=%v err=%v", ok, err)
	}
}

func TestOdysseyTransactionPreparedAndCancellation(t *testing.T) {
	_, sessionDSN := odysseyFixture(t)
	cfg, err := pgxpool.ParseConfig(sessionDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = "csar_authn"
	cfg.MaxConns = 3
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	client, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Release()
	query := "SELECT pg_backend_pid(), $1::integer + 1"
	var originalPID, pid, value int
	if err := client.QueryRow(ctx, query, 40).Scan(&originalPID, &value); err != nil || value != 41 {
		t.Fatalf("initial cached statement: value=%d err=%v", value, err)
	}
	// Occupy one backend; the first client's cached statement must also work
	// after Odyssey assigns it a different physical session.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var heldPID int
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&heldPID); err != nil {
		t.Fatal(err)
	}
	if err := client.QueryRow(ctx, query, 41).Scan(&pid, &value); err != nil || value != 42 || pid == heldPID {
		t.Fatalf("cached statement with occupied backend: value=%d err=%v", value, err)
	}
	t.Logf("prepared statement backend PIDs: initial=%d held=%d current=%d", originalPID, heldPID, pid)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	queryCtx, cancelQuery := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelQuery()
	if _, err := client.Exec(queryCtx, "SELECT pg_sleep(10)"); err == nil {
		t.Fatal("query timeout did not cancel")
	}
	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("pool did not recover after cancellation: %v", err)
	}
}
