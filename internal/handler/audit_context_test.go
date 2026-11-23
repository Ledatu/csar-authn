package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestOwnAuthenticationReplacesForgedAuditContext(t *testing.T) {
	h, st, sessions := newSessionsHandler(t, nil)
	u := &store.User{ID: uuid.New()}
	st.SeedUser(u)
	sess, err := sessions.Create(context.Background(), u.ID, "agent user agent", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.sessionMgr.IssueToken(u.ID.String(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"cookie", "jwt"} {
		t.Run(method, func(t *testing.T) {
			fake := &caller.Identity{Version: caller.Version, CallerKind: caller.Agent, CallerID: "forged", OwnerSubject: "other", EffectiveSubject: "other", CredentialKind: caller.APIKey, Assurance: caller.Verified}
			ctx := gatewayctx.NewContext(context.Background(), &gatewayctx.Identity{Subject: "other", RequestID: "request:1", Caller: fake, Origin: &gatewayctx.Origin{Caller: fake, OperationID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour)}})
			ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}}))
			r := httptest.NewRequest(http.MethodPost, "/auth/me/api-keys", nil).WithContext(ctx)
			if method == "cookie" {
				r.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
			} else {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			_, _, ok := h.authenticateRequest(httptest.NewRecorder(), r)
			if !ok {
				t.Fatal("valid own credential rejected")
			}
			id, _ := gatewayctx.FromContext(r.Context())
			if id.Subject != u.ID.String() || id.Caller == nil || id.Caller.CallerKind != caller.Human || id.Caller.OwnerSubject != u.ID.String() || id.Origin != nil || id.Caller.CredentialID != "" {
				t.Fatal("untrusted assertions survived own authentication")
			}
			h.recordAuditEvent(r, &audit.Event{Actor: "legacy-actor", Action: method, TargetType: "api_key", ScopeType: "subject"})
			events := h.auditRecorder.(*mockAuditRecorder).Events()
			event := events[len(events)-1]
			if event.Actor != "legacy-actor" || event.Caller == nil || event.Caller.CallerID != u.ID.String() || event.OriginCaller != nil || event.OperationID != "" || event.RequestID != "request:1" || event.TraceID == "" {
				t.Fatal("producer omitted verified metadata or retained forged origin")
			}
			encoded, err := json.Marshal(event)
			if err != nil || strings.Contains(string(encoded), sess.ID) || strings.Contains(string(encoded), token) {
				t.Fatal("audit exposed bearer material")
			}
		})
	}
}
