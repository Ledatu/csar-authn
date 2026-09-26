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

	"github.com/ledatu/csar-authn/internal/legacysync"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/gatewayctx"
)

const legacyUsersSyncSubject = "svc:legacy-identity-sync"

func newLegacyUsersSyncHandler(t *testing.T, enabled bool) (*Handler, func(subject, query, body string) *httptest.ResponseRecorder) {
	t.Helper()
	h, st, _ := newSessionsHandler(t, nil)
	h.legacyUsersSync = legacysync.NewService(st)
	cfg := *h.Config()
	cfg.LegacyUsersSync = authnconfig.LegacyUsersSyncConfig{
		Enabled:         enabled,
		AllowedSubjects: []string{legacyUsersSyncSubject},
		MaxUsers:        10,
	}
	h.SetConfig(&cfg)

	alice := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	st.SeedUser(&store.User{ID: alice, DisplayName: "Alice", Email: "alice@test.com"})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{Provider: "telegram", ProviderUserID: "111", UserID: alice}); err != nil {
		t.Fatal(err)
	}

	return h, func(subject, query, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/svc/authn/legacy-users-sync"+query, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if subject != "" {
			req.Header.Set(gatewayctx.HeaderSubject, subject)
		}
		w := httptest.NewRecorder()
		h.handleLegacyUsersSync(w, req)
		return w
	}
}

func legacyUsersSyncBody(users string) string {
	return `{"generated_at":"` + time.Now().UTC().Format(time.RFC3339) + `","users":` + users + `}`
}

func TestLegacyUsersSync_DryRunReportsWithoutProfileData(t *testing.T) {
	_, post := newLegacyUsersSyncHandler(t, true)

	w := post(legacyUsersSyncSubject, "?dry_run=true", legacyUsersSyncBody(`[
		{"legacy_id":111,"telegram_id":"111","yandex_id":"ya-1","first_name":"Alice","email":"alice-mongo@test.com"},
		{"legacy_id":222,"telegram_id":"222","first_name":"Bob","phone":"+79990001122"}
	]`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var report legacysync.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Users != 2 || report.Summary.Link != 1 || report.Summary.Create != 1 {
		t.Fatalf("summary = %+v", report.Summary)
	}
	for _, leaked := range []string{"Alice", "Bob", "alice-mongo@test.com", "alice@test.com", "79990001122"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Fatalf("report carries %q: %s", leaked, w.Body.String())
		}
	}
}

func TestLegacyUsersSync_Rejections(t *testing.T) {
	valid := legacyUsersSyncBody(`[{"legacy_id":111,"telegram_id":"111"}]`)
	cases := []struct {
		name    string
		enabled bool
		subject string
		query   string
		body    string
		want    int
	}{
		{"disabled", false, legacyUsersSyncSubject, "?dry_run=true", valid, http.StatusNotFound},
		{"no subject", true, "", "?dry_run=true", valid, http.StatusForbidden},
		{"other service", true, "svc:aurumskynet-campaigns", "?dry_run=true", valid, http.StatusForbidden},
		{"apply", true, legacyUsersSyncSubject, "?dry_run=false", valid, http.StatusBadRequest},
		{"no mode", true, legacyUsersSyncSubject, "", valid, http.StatusBadRequest},
		{"bad json", true, legacyUsersSyncSubject, "?dry_run=true", `{`, http.StatusBadRequest},
		{"empty users", true, legacyUsersSyncSubject, "?dry_run=true", legacyUsersSyncBody(`[]`), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, post := newLegacyUsersSyncHandler(t, tc.enabled)
			if w := post(tc.subject, tc.query, tc.body); w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
