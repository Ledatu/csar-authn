package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/lock"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/redis/go-redis/v9"
)

func dynamicMCPFixture(t *testing.T, client *http.Client) (*mcpDynamicClients, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	cache := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true, ReadTimeout: 200 * time.Millisecond, WriteTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = cache.Close() })
	limiter, err := usagebudget.New(cache, "test:mcp:", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return &mcpDynamicClients{cache: cache, http: client, limiter: limiter, locker: lock.NewRedisLocker(cache), slots: make(chan struct{}, 8)}, server
}

func TestMCPClientMetadataNegotiation(t *testing.T) {
	const id = "https://client.example/oauth/client.json"
	base := map[string]any{"client_id": id, "client_name": "An application", "redirect_uris": []string{"http://127.0.0.1:4000/callback", "https://client.example/callback"},
		"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"},
		"grant_types": []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"}, "response_types": []string{"code", "other"}}
	encode := func() []byte {
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	c, err := decodeMCPClient(encode(), id)
	if err != nil || c.AuthMethod != "none" || len(c.GrantTypes) != 2 || len(c.ResponseTypes) != 1 {
		t.Fatal("mutual capability selection failed", err)
	}
	if !publicOAuthRedirectAllowed(c, "http://127.0.0.1:4999/callback") || publicOAuthRedirectAllowed(c, "http://127.0.0.2:4999/callback") || publicOAuthRedirectAllowed(c, "https://client.example/callback/") {
		t.Fatal("callback binding or loopback-port rule failed")
	}
	c.RedirectURIs = []string{"http://localhost:4000/callback?source=native"}
	if publicOAuthRedirectAllowed(c, "http://localhost:4999/callback?source=native") {
		t.Fatal("non-native localhost port changed")
	}
	c.ApplicationType = "native"
	if !publicOAuthRedirectAllowed(c, "http://localhost:4999/callback?source=native") || publicOAuthRedirectAllowed(c, "http://localhost:4999/callback?source=other") {
		t.Fatal("native callback path/query binding failed")
	}
	for _, mutation := range []func(){
		func() { base["client_id"] = "https://other.example/client.json" },
		func() { base["client_secret"] = "must not be accepted" },
		func() { base["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"} },
		func() { base["redirect_uris"] = []string{"https://*.example/callback"} },
		func() { base["grant_types"] = []string{"client_credentials"} },
		func() { base["grant_types"] = nil },
		func() { base["response_types"] = nil },
		func() { base["token_endpoint_auth_method"] = nil },
		func() {
			base["token_endpoint_auth_method"] = "none"
			base["token_endpoint_auth_methods_supported"] = nil
		},
	} {
		original := encode()
		mutation()
		if _, err := decodeMCPClient(encode(), id); !errors.Is(err, errMCPClientMetadata) {
			t.Fatal("unsafe or incompatible metadata accepted")
		}
		if err := json.Unmarshal(original, &base); err != nil {
			t.Fatal(err)
		}
		delete(base, "client_secret")
	}
	for _, raw := range []string{"https://client.example/", "https://client.example/a/../client.json", "https://client.example/%2e%2e/client.json", "https://client.example/client.json?token=value", "https://user@client.example/client.json", "http://client.example/client.json"} {
		if validMCPMetadataURL(raw) {
			t.Fatal("unsafe metadata identifier accepted")
		}
	}
}

func TestMCPMetadataSharedCacheAndBoundedFailures(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("metadata request carried unexpected credentials or headers")
		}
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=120")
		_ = json.NewEncoder(w).Encode(store.MCPClient{ClientID: "https://" + r.Host + "/client.json", ClientName: "Fixture", RedirectURIs: []string{"https://client.example/callback"}, AuthMethod: "none", GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}})
	}))
	defer server.Close()
	id := server.URL + "/client.json"
	d, cache := dynamicMCPFixture(t, server.Client())
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			c, err := d.resolve(t.Context(), id)
			if err != nil || c.ClientID != id {
				t.Errorf("resolve: %v", err)
			}
			if err == nil {
				c.RedirectURIs[0] = "https://changed.example/callback"
			}
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("fetched %d times", calls.Load())
	}
	// A separate replica reuses the Redis document without its local flight map.
	other := &mcpDynamicClients{cache: d.cache}
	if c, err := other.resolve(t.Context(), id); err != nil || c.ClientName != "Fixture" {
		t.Fatal("replica did not use shared cache", err)
	}
	cache.FastForward(121 * time.Second)
	fail.Store(true)
	for range 2 {
		if _, err := d.resolve(t.Context(), id); !errors.Is(err, errMCPClientUnavailable) {
			t.Fatal("transient remote failure was not classified as unavailable", err)
		}
	}
	if calls.Load() != 3 {
		t.Fatal("an error response was cached")
	}
	cache.Close()
	if _, err := d.resolve(t.Context(), id); !errors.Is(err, errMCPClientUnavailable) {
		t.Fatal("Redis loss did not fail closed", err)
	}
	if calls.Load() != 3 {
		t.Fatal("Redis outage triggered additional remote fetches")
	}
}

func TestMCPAnonymousQuotaIgnoresUntrustedForwarding(t *testing.T) {
	d, _ := dynamicMCPFixture(t, http.DefaultClient)
	r := httptest.NewRequest(http.MethodPost, "/oauth/mcp/register", nil)
	r.RemoteAddr = "192.0.2.1:4000"
	for i := range 3 {
		r.Header.Set("X-Forwarded-For", strings.Repeat("1", i+1)+".example")
		err := d.admit(t.Context(), "mcp.test", requestPeer(r), 4, time.Minute)
		var exceeded *usagebudget.Exceeded
		if i < 2 && err != nil || i == 2 && !errors.As(err, &exceeded) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

func TestMCPMetadataCacheDirectives(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		control, age string
		want         time.Duration
	}{
		{"max-age=120", "30", 90 * time.Second}, {"max-age=120, s-maxage=10", "", 10 * time.Second},
		{"max-age=120, no-store", "", 0}, {"no-cache", "", 0}, {"private", "", 0},
		{"max-age=120, max-age=300", "", 0}, {"max-age=invalid", "", 0},
		{"max-age=3600", "", 10 * time.Minute}, {"max-age=10", "30", 0},
	} {
		header := http.Header{"Cache-Control": {tc.control}, "Age": {tc.age}, "Date": {now.Format(http.TimeFormat)}}
		if got := mcpMetadataTTL(header, now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.control, got, tc.want)
		}
	}
	if _, err := decodeMCPClient([]byte(strings.Repeat(" ", 65537)), ""); err == nil {
		t.Fatal("oversize metadata accepted")
	}
}
