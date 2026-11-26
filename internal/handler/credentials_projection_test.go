package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
)

func TestCredentialConsentProjectionPagesAndMixedCapacityPG(t *testing.T) {
	f := newCredentialFixture(t)
	f.u.cfg.Profiles[0].ManualIssuance = &authnconfig.CredentialManualIssuance{Family: "connection", MaxTTL: authnconfig.NewDuration(time.Hour)}
	for range 6 {
		f.issue(t)
	}
	legacy := &store.APICredential{ID: uuid.New(), OwnerID: f.owner.ID, SellerID: uuid.NewString(), Label: "Existing API", Scopes: []string{store.APIKeyScopeAdvertsRead}, TokenHash: hashValue("fixture-key"), Prefix: "aurum_sk_fixture", ExpiresAt: time.Now().Add(time.Hour)}
	if err := f.st.CreateAPICredential(t.Context(), legacy, 5); err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]bool{}
	for _, query := range []string{"?view=consent&kind=oauth_access&limit=5", "?view=consent&kind=oauth_access&limit=5&offset=5"} {
		w := f.send(t, "GET", "/auth/me/credentials"+query, nil, f.u.list, true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "token_hash") || strings.Contains(w.Body.String(), "pkce") || strings.Contains(w.Body.String(), "Bearer") {
			t.Fatal("secret data in owner projection")
		}
		var out struct {
			Version     int               `json:"version"`
			ConsentOnly bool              `json:"consent_only"`
			Items       []consentListItem `json:"items"`
			Next        *int              `json:"next_offset"`
			Capacity    map[string]struct {
				Active int `json:"active"`
				Limit  int `json:"limit"`
			} `json:"capacity"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Version != 1 || !out.ConsentOnly || out.Capacity["api_key"].Active != 1 || out.Capacity["api_key"].Limit != 5 || out.Capacity["oauth_access"].Active != 6 || out.Capacity["oauth_access"].Limit != 100 {
			t.Fatal("mixed-family caps lost", w.Body)
		}
		if strings.Contains(query, "offset=5") {
			if len(out.Items) != 1 || out.Next != nil {
				t.Fatal("wrong final page")
			}
		} else if len(out.Items) != 5 || out.Next == nil || *out.Next != 5 {
			t.Fatal("wrong first page")
		}
		for _, item := range out.Items {
			if seen[item.ID] || item.CallerLabel == "" || item.CallerKind != "agent" || item.Constraints.ProfileID != "workspace" || len(item.Constraints.Selection.Resources) != 1 {
				t.Fatal("missing/repeated metadata", item)
			}
			seen[item.ID] = true
		}
	}
	if len(seen) != 6 {
		t.Fatal("lost consent snapshot")
	}
	// Summary clients retain their original bounded contract.
	w := f.send(t, "GET", "/auth/me/credentials", nil, f.u.list, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"constraints"`) {
		t.Fatal("default summary changed")
	}
}
func TestCredentialConsentProjectionRejectsAmbiguousQueriesPG(t *testing.T) {
	f := newCredentialFixture(t)
	f.issue(t)
	for _, query := range []string{"?view=wrong", "?view=", "?view=consent&view=consent", "?view=consent&limit=6", "?view=consent&limit=-1", "?view=consent&offset=106", "?view=consent&kind=unknown", "?view=consent&profiles=workspace,workspace", "?view=consent&profile_id=workspace"} {
		w := f.send(t, "GET", "/auth/me/credentials"+query, nil, f.u.list, true)
		if w.Code != 400 {
			t.Fatal("unsafe query accepted", query, w.Code)
		}
	}
	w := f.send(t, "GET", "/auth/me/credentials?view=consent&profiles=other", nil, f.u.list, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal("foreign profile leaked")
	}
	req := httptest.NewRequest("GET", "/auth/me/credentials?view=consent", nil)
	w = httptest.NewRecorder()
	f.u.list(w, req)
	if w.Code != 401 {
		t.Fatal("owner session missing")
	}
}
