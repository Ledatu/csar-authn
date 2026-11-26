package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Exercise policy with real grants/callers/audit transactions; only routed Authz
// is a protocol fixture. Admission has no product names or consent resource IDs.
func enableAdmission(t *testing.T, f *credentialFixture) *string {
	t.Helper()
	mode := "allow"
	p := &f.u.cfg.Profiles[0]
	p.Admission = &authnconfig.CredentialAdmission{DecisionProfile: "entry-policy", Resource: authntokens.ResourceRef{Namespace: "enrollment", ID: "restricted-profile"}, RequiredScope: authntokens.ScopeRef{Type: "platform"}}
	original := f.u.decisions.Client.Transport
	f.u.decisions.Client.Transport = credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var in struct {
			Version                    int `json:"version"`
			Profile, Audience, Subject string
			Mode                       string `json:"subject_mode"`
			Resources                  []authntokens.ResourceRef
		}
		if json.Unmarshal(raw, &in) != nil {
			t.Fatal("invalid decision")
		}
		if in.Profile != "entry-policy" {
			return original.RoundTrip(r)
		}
		if in.Version != 1 || in.Subject != f.owner.ID.String() || in.Mode != "background" || in.Audience != p.Audience || len(in.Resources) != 1 || in.Resources[0] != p.Admission.Resource {
			t.Fatal("admission binding changed")
		}
		if mode == "unavailable" {
			return nil, errors.New("fixture unavailable")
		}
		result := credentialDecision{Resource: in.Resources[0], Allowed: mode != "deny"}
		if result.Allowed {
			result.Scope = &authntokens.ScopeRef{Type: "platform"}
		}
		if mode == "tenant" {
			result.Scope = &authntokens.ScopeRef{Type: "tenant", ID: "enrollment:restricted-profile"}
		}
		if mode == "resource" {
			result.Resource.ID = "other"
		}
		out := map[string]any{"version": 1, "profile": in.Profile, "audience": in.Audience, "subject": in.Subject, "results": []credentialDecision{result}}
		if mode == "audience" {
			out["audience"] = "https://foreign.example.test"
		}
		data, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})
	return &mode
}

func TestProfileAdmissionKeepsAPIAvailableAndGatesCurrentAuthorityPG(t *testing.T) {
	f := newCredentialFixture(t)
	mode := enableAdmission(t, f)
	token, id := f.issue(t)
	for _, tc := range []struct {
		mode string
		want int
	}{{"deny", 403}, {"tenant", 403}, {"unavailable", 503}, {"audience", 503}, {"resource", 503}} {
		*mode = tc.mode
		w := f.send(t, "POST", "/auth/me/credentials", map[string]any{"profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "current_and_future"}, "label": "denied", "caller_kind": "agent"}, f.u.create, true)
		if w.Code != tc.want {
			t.Fatal(tc.mode, w.Code, w.Body)
		}
		if _, _, _, err := f.u.state(t.Context(), token, store.SecretAccess); err == nil {
			t.Fatal("lost admission left current authority usable", tc.mode)
		}
	}
	// Policy denial changes no original deadline, consent or persisted key state.
	g, err := f.st.GetCredentialGrant(t.Context(), f.owner.ID, id)
	if err != nil || g.RevokedAt != nil {
		t.Fatal("admission changed credential state", err)
	}
	// An unrelated profile has no admission network dependency and still issues.
	api := f.u.cfg.Profiles[0]
	api.ID = "ordinary-api"
	api.Admission = nil
	f.u.cfg.Profiles = append(f.u.cfg.Profiles, api)
	*mode = "unavailable"
	w := f.send(t, "POST", "/auth/me/credentials", map[string]any{"profile_id": "ordinary-api", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "current_and_future"}, "label": "api", "caller_kind": "application"}, f.u.create, true)
	if w.Code != 201 {
		t.Fatal("API profile inherited admission", w.Code, w.Body)
	}
	*mode = "deny"
	w = f.send(t, "DELETE", "/auth/me/credentials/"+id.String(), nil, func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("grant_id", id.String())
		f.u.revoke(w, r)
	}, true)
	if w.Code != 204 {
		t.Fatal("owner could not revoke after admission loss", w.Code, w.Body)
	}
}

func TestProfileAdmissionGatesOAuthConsentWithoutBlockingDenialPG(t *testing.T) {
	f := newCredentialFixture(t)
	mode := enableAdmission(t, f)
	client := store.OAuthClient{ClientID: "https://client.example.test/admission", ClientName: "Client", RedirectURIs: []string{"https://client.example.test/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, AuthMethod: "none"}
	if _, err := f.st.RegisterOAuthClient(t.Context(), client, strings.Repeat("c", 64), 4096); err != nil {
		t.Fatal(err)
	}
	w := f.send(t, "POST", "/oauth/credentials/authorize", map[string]any{"profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "client_id": client.ClientID, "redirect_uri": client.RedirectURIs[0], "code_challenge_method": "S256", "code_challenge": oauth2.S256ChallengeFromVerifier(strings.Repeat("A", 43))}, f.u.beginAuthorization, false)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var started struct {
		ID string `json:"request_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &started) != nil || started.ID == "" {
		t.Fatal("missing request")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == f.u.cfg.ConsentCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing browser nonce")
	}
	send := func(method, path string, body any, fn http.HandlerFunc) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Origin", "https://console.example.test")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(f.cookie)
		r.AddCookie(cookie)
		r.SetPathValue("request_id", started.ID)
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	*mode = "deny"
	if w := send("GET", "/oauth/credentials/requests/"+started.ID, nil, f.u.authorizationInfo); w.Code != 403 {
		t.Fatal("consent metadata admission bypass", w.Code, w.Body)
	}
	body := map[string]any{"request_id": started.ID, "profile_id": "workspace", "scopes": []string{"facts:read"}, "namespaces": []string{"workspace"}, "selection": map[string]any{"mode": "current_and_future"}, "label": "OAuth", "caller_kind": "application"}
	if w := send("POST", "/oauth/credentials/approve", body, f.u.approveAuthorization); w.Code != 403 {
		t.Fatal("consent admission bypass", w.Code, w.Body)
	}
	if w := send("POST", "/oauth/credentials/deny", map[string]string{"request_id": started.ID}, f.u.denyAuthorization); w.Code != 200 {
		t.Fatal("owner could not deny after admission loss", w.Code, w.Body)
	}
}
