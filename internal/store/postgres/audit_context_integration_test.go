package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"go.opentelemetry.io/otel/trace"
)

func TestTransactionalProducersRetainRequestIdentity(t *testing.T) {
	s := auditFixture(t)
	u, err := s.CreateUser(context.Background(), &store.User{DisplayName: "synthetic audit owner"})
	if err != nil {
		t.Fatal(err)
	}
	id := &caller.Identity{Version: caller.Version, CallerKind: caller.Human, CallerID: u.ID.String(), OwnerSubject: u.ID.String(), EffectiveSubject: u.ID.String(), CredentialKind: caller.Session, Assurance: caller.Verified}
	ctx := gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Subject: u.ID.String(), Caller: id, RequestID: "request:1"})
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}}))
	registered := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Agent, Label: "synthetic agent"}
	if err := s.CreateCaller(ctx, registered, 20); err != nil {
		t.Fatal(err)
	}
	key := &store.APICredential{ID: uuid.New(), OwnerID: u.ID, CallerID: &registered.ID, SellerID: uuid.NewString(), Label: "synthetic", TokenHash: strings.Repeat("f", 64), Prefix: "test-only-prefix", Scopes: []string{store.APIKeyScopeAnalyticsRead}, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateAPICredential(ctx, key, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrReactivateServiceAccount(ctx, &store.ServiceAccount{Name: "test:audit", PublicKeyPEM: "test-only-public-key", AllowedAudiences: []string{"test"}, TokenTTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM csar_audit_outbox`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var e audit.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if e.Caller == nil || *e.Caller != *id || e.Actor != u.ID.String() || e.RequestID != "request:1" || e.TraceID != "01000000000000000000000000000000" || e.Service != "csar-authn" || e.ID == "" || e.CreatedAt.IsZero() {
			t.Fatal("durable producer lost verified request context", e.Action)
		}
		if strings.Contains(string(raw), key.TokenHash) || strings.Contains(string(raw), key.Prefix) || strings.Contains(string(raw), "test-only-public-key") {
			t.Fatal("outbox contains credential material")
		}
		seen[e.Action] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"credentials.caller.create", "credentials.caller.bind", "api_key.create", "service_account.create"} {
		if !seen[action] {
			t.Fatal("producer missing", action)
		}
	}
	bad := &store.Caller{ID: uuid.New(), OwnerID: u.ID, Kind: caller.Application, Label: "must rollback"}
	invalid := gatewayctx.NewContext(ctx, &gatewayctx.Identity{Subject: u.ID.String(), Caller: &caller.Identity{Version: 999}})
	if err := s.CreateCaller(invalid, bad, 20); err == nil {
		t.Fatal("invalid audit context committed a registration")
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM registered_callers WHERE id=$1)`, bad.ID).Scan(&exists); err != nil || exists {
		t.Fatal("failed attribution did not roll back mutation", err)
	}
}
