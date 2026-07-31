package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func seedTelegramUser(t *testing.T, st *mock.Store, userID uuid.UUID, tgID, displayName string, metadata map[string]interface{}) {
	t.Helper()
	st.SeedUser(&store.User{ID: userID, DisplayName: displayName})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:         "telegram",
		ProviderUserID:   tgID,
		UserID:           userID,
		DisplayName:      displayName,
		ProviderMetadata: metadata,
	}); err != nil {
		t.Fatal(err)
	}
}

func postBrowser(t *testing.T, h *Handler, token, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	switch path {
	case "/auth/users/resolve":
		h.handleResolveBrowserUsers(rec, req)
	case "/auth/users/lookup":
		h.handleLookupBrowserUser(rec, req)
	default:
		t.Fatalf("unexpected path %q", path)
	}
	return rec
}

func decodeResolve(t *testing.T, rec *httptest.ResponseRecorder) browserUserResolveResponse {
	t.Helper()
	var resp browserUserResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	return resp
}

func TestResolveBrowserUsers_ByTelegramID(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	seedTelegramUser(t, st, uuid.MustParse("22222222-2222-4222-8222-222222222222"), "111", "Ivan Petrov", nil)
	seedTelegramUser(t, st, uuid.MustParse("33333333-3333-4333-8333-333333333333"), "222", "Anna Ivanova",
		map[string]interface{}{"legacy_username": "@annai"})

	rec := postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "telegram",
		IDs:      []string{"111", "222", "999"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	resp := decodeResolve(t, rec)
	// The unknown id is omitted, not nulled.
	if len(resp.Users) != 2 {
		t.Fatalf("got %d users, want 2: %+v", len(resp.Users), resp.Users)
	}

	byTG := map[string]browserUserItem{}
	for _, u := range resp.Users {
		byTG[u.ProviderUserID] = u
	}
	if got := byTG["111"].DisplayName; got != "Ivan Petrov" {
		t.Errorf("display_name = %q, want %q", got, "Ivan Petrov")
	}
	if got := byTG["111"].Username; got != "" {
		t.Errorf("username = %q, want empty when no legacy_username", got)
	}
	// The stored handle carries a leading @; the wire value must not.
	if got := byTG["222"].Username; got != "annai" {
		t.Errorf("username = %q, want %q", got, "annai")
	}
	if byTG["222"].ID != "33333333-3333-4333-8333-333333333333" {
		t.Errorf("id = %q, want the authn uuid", byTG["222"].ID)
	}
}

// Locked decision: this endpoint is reachable by any authenticated seller, so it
// must never carry PII. Guards the response shape against a future struct edit.
func TestResolveBrowserUsers_CarriesNoPII(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	userID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	st.SeedUser(&store.User{ID: userID, DisplayName: "Has Contact", Email: "leak@test.com", Phone: "+70000000000"})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider: "telegram", ProviderUserID: "555", UserID: userID,
	}); err != nil {
		t.Fatal(err)
	}

	rec := postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "telegram", IDs: []string{"555"},
	})

	var raw struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(raw.Users))
	}
	for _, forbidden := range []string{"email", "phone", "linked_accounts"} {
		if _, present := raw.Users[0][forbidden]; present {
			t.Errorf("response leaks %q: %v", forbidden, raw.Users[0])
		}
	}
}

// Merged accounts must resolve to the canonical user rather than the stale record.
func TestResolveBrowserUsers_FollowsMerge(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	canonical := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	merged := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	st.SeedUser(&store.User{ID: canonical, DisplayName: "Canonical Name"})
	st.SeedUser(&store.User{ID: merged, DisplayName: "Stale Name", MergedInto: &canonical})
	if err := st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider: "telegram", ProviderUserID: "888", UserID: merged,
	}); err != nil {
		t.Fatal(err)
	}

	rec := postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "telegram", IDs: []string{"888"},
	})
	resp := decodeResolve(t, rec)
	if len(resp.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(resp.Users))
	}
	if resp.Users[0].ID != canonical.String() {
		t.Errorf("id = %q, want canonical %q", resp.Users[0].ID, canonical)
	}
	if resp.Users[0].DisplayName != "Canonical Name" {
		t.Errorf("display_name = %q, want the canonical user's", resp.Users[0].DisplayName)
	}
	// The requested telegram id is still echoed so the client can key by it.
	if resp.Users[0].ProviderUserID != "888" {
		t.Errorf("provider_user_id = %q, want the requested id", resp.Users[0].ProviderUserID)
	}
}

func TestResolveBrowserUsers_RejectsOverCapAndBadProvider(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	over := make([]string, maxBrowserUserResolveIDs+1)
	for i := range over {
		over[i] = strconv.Itoa(i)
	}
	// Reject, never truncate: a silently dropped tail renders as blank cards.
	rec := postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "telegram", IDs: over,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("over-cap status = %d, want 400", rec.Code)
	}

	rec = postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "google", IDs: []string{"111"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-allowlisted provider status = %d, want 400", rec.Code)
	}
}

func TestResolveBrowserUsers_EmptyInputReturnsEmptyArray(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	rec := postBrowser(t, h, token, "/auth/users/resolve", browserUserResolveRequest{
		Provider: "telegram", IDs: []string{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Must serialize as [] rather than null so clients can iterate unconditionally.
	if got := rec.Body.String(); !bytes.Contains([]byte(got), []byte(`"users":[]`)) {
		t.Errorf("body = %s, want an empty array", got)
	}
}

func TestResolveBrowserUsers_RequiresSession(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/users/resolve", bytes.NewReader([]byte(`{"provider":"telegram","ids":["1"]}`)))
	rec := httptest.NewRecorder()
	h.handleResolveBrowserUsers(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestLookupBrowserUser(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	userID := uuid.MustParse("99999999-9999-4999-8999-999999999999")
	seedTelegramUser(t, st, userID, "12345", "Lookup Target", nil)

	t.Run("by telegram id", func(t *testing.T) {
		rec := postBrowser(t, h, token, "/auth/users/lookup", browserUserLookupRequest{Identifier: "12345"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var resp browserUserLookupResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.User.ID != userID.String() {
			t.Errorf("id = %q, want %q", resp.User.ID, userID)
		}
	})

	t.Run("by uuid returns the telegram link", func(t *testing.T) {
		rec := postBrowser(t, h, token, "/auth/users/lookup", browserUserLookupRequest{Identifier: userID.String()})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		var resp browserUserLookupResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		// The client needs this to talk to the legacy member endpoints.
		if resp.User.ProviderUserID != "12345" {
			t.Errorf("provider_user_id = %q, want %q", resp.User.ProviderUserID, "12345")
		}
	})

	t.Run("unknown identifier is 404", func(t *testing.T) {
		rec := postBrowser(t, h, token, "/auth/users/lookup", browserUserLookupRequest{Identifier: "404404404"})
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	// Exact match only: a handle or any other free text must not become a search.
	t.Run("non-exact identifiers never match", func(t *testing.T) {
		for _, identifier := range []string{"@lookuptarget", "Lookup", "123", "' OR 1=1"} {
			rec := postBrowser(t, h, token, "/auth/users/lookup", browserUserLookupRequest{Identifier: identifier})
			if rec.Code != http.StatusNotFound {
				t.Errorf("identifier %q: status = %d, want 404", identifier, rec.Code)
			}
		}
	})

	t.Run("empty identifier is 400", func(t *testing.T) {
		rec := postBrowser(t, h, token, "/auth/users/lookup", browserUserLookupRequest{Identifier: "  "})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

// The /svc contract is keyed by the requested id. Merge-following must not
// change that field, or aurumskynet-campaigns' profiles map stops matching and
// member cards silently render blank.
func TestResolveServiceUsers_EchoesRequestedIDAcrossMerge(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)

	canonical := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	merged := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	st.SeedUser(&store.User{ID: canonical, DisplayName: "Canonical Name"})
	st.SeedUser(&store.User{ID: merged, DisplayName: "Stale Name", MergedInto: &canonical})

	body, _ := json.Marshal(serviceUserResolveRequest{IDs: []string{merged.String()}})
	req := httptest.NewRequest(http.MethodPost, "/svc/authn/users/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleResolveServiceUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp serviceUserResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(resp.Users))
	}
	if resp.Users[0].ID != merged.String() {
		t.Errorf("id = %q, want the requested id %q", resp.Users[0].ID, merged)
	}
	// Display data still comes from the canonical user.
	if resp.Users[0].DisplayName != "Canonical Name" {
		t.Errorf("display_name = %q, want %q", resp.Users[0].DisplayName, "Canonical Name")
	}
}

// The /svc response shape is decoded into a fixed struct by
// aurumskynet-campaigns; it must not grow browser-only fields.
func TestResolveServiceUsers_ShapeUnchanged(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)

	userID := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	seedTelegramUser(t, st, userID, "777", "Svc User", map[string]interface{}{"legacy_username": "svcuser"})

	body, _ := json.Marshal(serviceUserResolveRequest{IDs: []string{userID.String()}})
	req := httptest.NewRequest(http.MethodPost, "/svc/authn/users/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleResolveServiceUsers(rec, req)

	var raw struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(raw.Users))
	}
	for _, unexpected := range []string{"provider_user_id", "username", "provider"} {
		if _, present := raw.Users[0][unexpected]; present {
			t.Errorf("svc response gained field %q, which its consumers do not expect", unexpected)
		}
	}
}
