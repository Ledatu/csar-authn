package avatar

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// DefaultSignedURLCacheTTL must stay comfortably below the read-link TTL
	// csar-s3 issues (15m in prod), so a URL served at the end of a cache window
	// still has meaningful life left in the browser.
	DefaultSignedURLCacheTTL = 10 * time.Minute

	// DefaultSignedURLCacheSize bounds memory. Entries are small; the limit
	// exists to stop an unbounded set of storage keys from accumulating.
	DefaultSignedURLCacheSize = 10000

	// negativeTTL keeps a failure sticky just long enough that one missing
	// object cannot make every render re-issue a full batch of failing calls,
	// while still recovering from a transient csar-s3 outage quickly.
	negativeTTL = 10 * time.Second
)

type signedURLEntry struct {
	url       string
	err       error
	expiresAt time.Time
}

// CachingClient memoizes signed read URLs. Without it, resolving a batch of
// users issues one HTTP round trip to csar-s3 per avatar storage key — up to two
// per user — which does not survive a 200-id directory request.
type CachingClient struct {
	*Client

	ttl     time.Duration
	maxSize int
	now     func() time.Time

	group singleflight.Group

	mu      sync.RWMutex
	entries map[string]signedURLEntry
}

// NewCachingClient wraps c with a bounded TTL cache. A nil client returns nil so
// callers can keep passing an optional avatar client through unchanged.
func NewCachingClient(c *Client, ttl time.Duration, maxSize int) *CachingClient {
	if c == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultSignedURLCacheTTL
	}
	if maxSize <= 0 {
		maxSize = DefaultSignedURLCacheSize
	}
	return &CachingClient{
		Client:  c,
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
		entries: make(map[string]signedURLEntry),
	}
}

func (c *CachingClient) SignedReadURL(ctx context.Context, storageKey string) (string, error) {
	if storageKey == "" {
		return "", nil
	}

	if url, err, ok := c.lookup(storageKey); ok {
		return url, err
	}

	// singleflight collapses the stampede that a cold cache plus a large batch
	// would otherwise produce for repeated keys.
	url, err, _ := c.group.Do(storageKey, func() (interface{}, error) {
		if url, err, ok := c.lookup(storageKey); ok {
			return url, err
		}
		url, err := c.Client.SignedReadURL(ctx, storageKey)
		c.store(storageKey, url, err)
		return url, err
	})
	if err != nil {
		return "", err
	}
	return url.(string), nil
}

func (c *CachingClient) lookup(storageKey string) (string, error, bool) {
	c.mu.RLock()
	entry, ok := c.entries[storageKey]
	c.mu.RUnlock()
	if !ok || !c.now().Before(entry.expiresAt) {
		return "", nil, false
	}
	return entry.url, entry.err, true
}

func (c *CachingClient) store(storageKey, url string, err error) {
	ttl := c.ttl
	if err != nil {
		ttl = negativeTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[storageKey] = signedURLEntry{url: url, err: err, expiresAt: c.now().Add(ttl)}
}

// evictLocked drops expired entries, falling back to clearing the map when the
// cache is full of live entries. Signed URLs are cheap to re-derive, so a hard
// reset is preferable to tracking per-entry access order.
func (c *CachingClient) evictLocked() {
	now := c.now()
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	if len(c.entries) >= c.maxSize {
		c.entries = make(map[string]signedURLEntry)
	}
}
