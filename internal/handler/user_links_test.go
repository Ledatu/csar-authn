package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/gatewayctx"
)

func postServiceUserLinks(t *testing.T, h *Handler, subject, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/svc/authn/users/resolve-links", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if subject != "" {
		req.Header.Set(gatewayctx.HeaderSubject, subject)
	}
	w := httptest.NewRecorder()
	h.handleResolveServiceUserLinks(w, req)
	return w
}

func TestServiceUserLinks_ResolvesTelegramAndYandex(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	ctx := context.Background()

	alice := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	bob := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	st.SeedUser(&store.User{ID: alice, DisplayName: "Alice", Email: "alice@test.com"})
	st.SeedUser(&store.User{ID: bob, DisplayName: "Bob"})
	for _, acct := range []*store.OAuthAccount{
		{Provider: "telegram", ProviderUserID: "111", UserID: alice},
		{Provider: "yandex", ProviderUserID: "222", UserID: bob},
	} {
		if err := st.CreateOAuthAccount(ctx, acct); err != nil {
			t.Fatal(err)
		}
	}

	w := postServiceUserLinks(t, h, "svc:aurumskynet-campaigns", `{"provider":"telegram","ids":["111","111","999","not-numeric"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp serviceUserLinkResolveResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Links) != 1 || resp.Links[0] != (serviceUserLink{ProviderUserID: "111", UserID: alice.String()}) {
		t.Fatalf("telegram links = %+v", resp.Links)
	}
	if strings.Contains(w.Body.String(), "alice@test.com") || strings.Contains(w.Body.String(), "Alice") {
		t.Fatalf("response carries profile data: %s", w.Body.String())
	}

	w = postServiceUserLinks(t, h, "svc:aurumskynet-campaigns", `{"provider":"Yandex","ids":["222"]}`)
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Links) != 1 || resp.Links[0].UserID != bob.String() {
		t.Fatalf("yandex links = %+v", resp.Links)
	}
}

func TestServiceUserLinks_EmptyIDsReturnEmptyList(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)

	w := postServiceUserLinks(t, h, "svc:aurumskynet-campaigns", `{"provider":"telegram","ids":[]}`)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"links":[]}` {
		t.Fatalf("got %d %s, want 200 {\"links\":[]}", w.Code, w.Body.String())
	}
}

func TestServiceUserLinks_Rejections(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)
	tooMany, _ := json.Marshal(serviceUserLinkResolveRequest{
		Provider: "telegram",
		IDs:      make([]string, maxServiceUserLinkResolveIDs+1),
	})

	cases := []struct {
		name    string
		subject string
		body    string
		want    int
	}{
		{"no subject", "", `{"provider":"telegram","ids":["1"]}`, http.StatusForbidden},
		{"user subject", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", `{"provider":"telegram","ids":["1"]}`, http.StatusForbidden},
		{"unsupported provider", "svc:aurumskynet-campaigns", `{"provider":"google","ids":["1"]}`, http.StatusBadRequest},
		{"aurum provider", "svc:aurumskynet-campaigns", `{"provider":"aurum","ids":["1"]}`, http.StatusBadRequest},
		{"too many ids", "svc:aurumskynet-campaigns", string(tooMany), http.StatusBadRequest},
		{"malformed", "svc:aurumskynet-campaigns", `{`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := postServiceUserLinks(t, h, tc.subject, tc.body); w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
