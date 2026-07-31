package avatar

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestCachingClient(t *testing.T, handler http.HandlerFunc) (*CachingClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
		logger:     slog.Default(),
	}
	return NewCachingClient(client, time.Minute, 100), srv
}

func readLinkHandler(calls *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"link":{"url":"https://signed.example/object"}}`))
	}
}

func TestCachingClient_ServesSecondCallFromCache(t *testing.T) {
	var calls atomic.Int64
	c, _ := newTestCachingClient(t, readLinkHandler(&calls))

	for i := 0; i < 5; i++ {
		url, err := c.SignedReadURL(context.Background(), "key-a")
		if err != nil {
			t.Fatal(err)
		}
		if url != "https://signed.example/object" {
			t.Fatalf("url = %q", url)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestCachingClient_ExpiresAfterTTL(t *testing.T) {
	var calls atomic.Int64
	c, _ := newTestCachingClient(t, readLinkHandler(&calls))

	now := time.Now()
	c.now = func() time.Time { return now }

	if _, err := c.SignedReadURL(context.Background(), "key-a"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.SignedReadURL(context.Background(), "key-a"); err != nil {
		t.Fatal(err)
	}

	if got := calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 after expiry", got)
	}
}

// A cold batch resolving the same key concurrently must not stampede csar-s3.
func TestCachingClient_CollapsesConcurrentMisses(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	c, _ := newTestCachingClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"link":{"url":"https://signed.example/object"}}`))
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.SignedReadURL(context.Background(), "shared-key"); err != nil {
				t.Error(err)
			}
		}()
	}

	// Give the goroutines a chance to pile up on the same singleflight key.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestCachingClient_NegativelyCachesFailures(t *testing.T) {
	var calls atomic.Int64
	c, _ := newTestCachingClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	now := time.Now()
	c.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, err := c.SignedReadURL(context.Background(), "missing"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1 while negatively cached", got)
	}

	// Recovers once the short negative window elapses.
	now = now.Add(negativeTTL + time.Second)
	if _, err := c.SignedReadURL(context.Background(), "missing"); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 after the negative entry expired", got)
	}
}

func TestCachingClient_BoundsSize(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(readLinkHandler(&calls))
	t.Cleanup(srv.Close)

	c := NewCachingClient(&Client{baseURL: srv.URL, httpClient: srv.Client(), logger: slog.Default()}, time.Minute, 10)

	for i := 0; i < 100; i++ {
		if _, err := c.SignedReadURL(context.Background(), "key-"+string(rune('a'+i%26))+string(rune('a'+i/26))); err != nil {
			t.Fatal(err)
		}
	}

	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	if size > 10 {
		t.Errorf("cache holds %d entries, want at most 10", size)
	}
}

func TestCachingClient_EmptyKeyAndNilClient(t *testing.T) {
	var calls atomic.Int64
	c, _ := newTestCachingClient(t, readLinkHandler(&calls))

	url, err := c.SignedReadURL(context.Background(), "")
	if err != nil || url != "" {
		t.Errorf("empty key: url=%q err=%v, want empty and nil", url, err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("upstream calls = %d, want 0 for an empty key", got)
	}

	// A nil client stays nil so callers can keep an optional dependency optional.
	if NewCachingClient(nil, time.Minute, 10) != nil {
		t.Error("NewCachingClient(nil) should return nil")
	}
}

