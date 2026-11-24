package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar-core/httpx/clientx"
	"github.com/ledatu/csar-core/lock"
	"github.com/ledatu/csar-core/usagebudget"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

var errMCPClientUnavailable = errors.New("OAuth client metadata unavailable")

type mcpDynamicClients struct {
	store   store.MCPClientStore
	cache   *redis.Client
	http    *http.Client
	limiter *usagebudget.Limiter
	locker  lock.Locker
	flight  singleflight.Group
	slots   chan struct{}
}

func (d *mcpDynamicClients) admit(ctx context.Context, policy, peer string, capacity int64, window time.Duration) error {
	return d.limiter.Take(ctx, usagebudget.Request{Policy: policy, Window: window, Units: 1,
		Limits: []usagebudget.Limit{{Dimension: "global", Subject: "issuer", Capacity: capacity},
			{Dimension: "peer", Subject: hashValue(peer), Capacity: capacity / 2}}})
}

func requestPeer(r *http.Request) string {
	// This is deliberately the socket peer, not an unverified X-Forwarded-For.
	// Edge routes additionally enforce their trusted client-IP policy.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (d *mcpDynamicClients) cached(ctx context.Context, key, id string) (store.MCPClient, bool, error) {
	var c store.MCPClient
	raw, err := d.cache.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return c, false, nil
	}
	if err != nil || len(raw) > 65536 {
		return c, false, errMCPClientUnavailable
	}
	parsed, err := decodeMCPClient(raw, id)
	if err != nil {
		return c, false, errMCPClientUnavailable
	}
	return parsed, true, nil
}

func (d *mcpDynamicClients) resolve(ctx context.Context, id string) (store.MCPClient, error) {
	if strings.HasPrefix(id, "dcr_") {
		return d.store.MCPClient(ctx, id)
	}
	if !validMCPMetadataURL(id) {
		return store.MCPClient{}, errMCPClientMetadata
	}
	key := "authn:mcp:metadata:" + hashValue(id)
	if c, ok, err := d.cached(ctx, key, id); err != nil || ok {
		return c, err
	}
	result := d.flight.DoChan(key, func() (any, error) {
		fetchCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		select {
		case d.slots <- struct{}{}:
			defer func() { <-d.slots }()
		default:
			return nil, errMCPClientUnavailable
		}
		if c, ok, err := d.cached(fetchCtx, key, id); err != nil || ok {
			return c, err
		}
		release, err := d.locker.Acquire(fetchCtx, key+":fetch", 5*time.Second)
		if err != nil {
			for range 5 {
				select {
				case <-fetchCtx.Done():
					return nil, errMCPClientUnavailable
				case <-time.After(100 * time.Millisecond):
				}
				if c, ok, err := d.cached(fetchCtx, key, id); err != nil || ok {
					return c, err
				}
			}
			return nil, errMCPClientUnavailable
		}
		defer func() { _ = release() }()
		if err := d.admit(fetchCtx, "mcp.metadata.fetch", hashValue(id), 120, time.Hour); err != nil {
			return nil, err
		}
		return d.fetch(fetchCtx, key, id)
	})
	select {
	case <-ctx.Done():
		return store.MCPClient{}, ctx.Err()
	case result := <-result:
		if result.Err != nil {
			return store.MCPClient{}, result.Err
		}
		c, ok := result.Val.(store.MCPClient)
		if !ok {
			return c, errMCPClientUnavailable
		}
		// Return owned slices to each waiter.
		c.RedirectURIs = slices.Clone(c.RedirectURIs)
		c.GrantTypes = slices.Clone(c.GrantTypes)
		c.ResponseTypes = slices.Clone(c.ResponseTypes)
		return c, nil
	}
}

func (d *mcpDynamicClients) fetch(ctx context.Context, key, id string) (store.MCPClient, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return store.MCPClient{}, errMCPClientMetadata
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		if errors.Is(err, clientx.ErrNonPublicDestination) {
			return store.MCPClient{}, errMCPClientMetadata
		}
		return store.MCPClient{}, errMCPClientUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
		return store.MCPClient{}, errMCPClientUnavailable
	}
	if resp.StatusCode != http.StatusOK || media != "application/json" && (!strings.HasPrefix(media, "application/") || !strings.HasSuffix(media, "+json")) {
		return store.MCPClient{}, errMCPClientMetadata
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return store.MCPClient{}, errMCPClientUnavailable
	}
	c, err := decodeMCPClient(raw, id)
	if err != nil {
		return c, err
	}
	if ttl := mcpMetadataTTL(resp.Header, time.Now()); ttl > 0 {
		// Store only validated, normalized metadata; errors and malformed documents
		// are never cached. Throttling bounds repeated failures independently.
		encoded, err := json.Marshal(c)
		if err != nil || d.cache.Set(ctx, key, encoded, ttl).Err() != nil {
			return c, errMCPClientUnavailable
		}
	}
	return c, nil
}

func mcpMetadataTTL(header http.Header, now time.Time) time.Duration {
	ttl := time.Minute
	var maxAge, sharedMaxAge *time.Duration
	for _, directive := range strings.Split(strings.Join(header.Values("Cache-Control"), ","), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		switch name {
		case "no-store", "no-cache", "private":
			return 0
		case "max-age", "s-maxage":
			n, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 32)
			if err != nil || n < 0 {
				return 0
			}
			value := time.Duration(n) * time.Second
			if name == "s-maxage" {
				if sharedMaxAge != nil {
					return 0
				}
				sharedMaxAge = &value
			} else {
				if maxAge != nil {
					return 0
				}
				maxAge = &value
			}
		}
	}
	date, err := http.ParseTime(header.Get("Date"))
	if err != nil {
		date = now
	}
	age := max(time.Duration(0), now.Sub(date))
	if rawAge := header.Get("Age"); rawAge != "" {
		n, err := strconv.ParseInt(rawAge, 10, 32)
		if err != nil || n < 0 {
			return 0
		}
		age = max(age, time.Duration(n)*time.Second)
	}
	if maxAge != nil {
		ttl = *maxAge
	}
	if sharedMaxAge != nil {
		ttl = *sharedMaxAge
	}
	if maxAge == nil && sharedMaxAge == nil && header.Get("Expires") != "" {
		expires, err := http.ParseTime(header.Get("Expires"))
		if err != nil {
			return 0
		}
		ttl = expires.Sub(date)
	}
	ttl -= age
	if ttl < 0 {
		return 0
	}
	if ttl > 10*time.Minute {
		return 10 * time.Minute
	}
	return ttl
}

func (o *sellerOAuth) registerClient(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := o.dynamic.admit(r.Context(), "mcp.registration", requestPeer(r), 100, time.Hour); err != nil {
		o.clientError(w, err)
		return
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	raw, err := io.ReadAll(r.Body)
	if err != nil || media != "application/json" {
		oauthError(w, 400, "invalid_client_metadata")
		return
	}
	c, err := decodeMCPClient(raw, "")
	if err != nil {
		oauthError(w, 400, "invalid_client_metadata")
		return
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		o.clientError(w, err)
		return
	}
	c.ClientID, c.IssuedAt = "dcr_"+randomToken(), time.Now().Unix()
	c, err = o.dynamic.store.RegisterMCPClient(r.Context(), c, hashValue(string(canonical)), 4096)
	if err != nil {
		o.clientError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (o *sellerOAuth) clientError(w http.ResponseWriter, err error) {
	var exceeded *usagebudget.Exceeded
	switch {
	case errors.As(err, &exceeded):
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(exceeded.RetryAfter.Seconds())+1)))
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable")
	case errors.Is(err, errMCPClientMetadata), errors.Is(err, store.ErrNotFound):
		oauthError(w, 400, "invalid_client")
	default:
		oauthError(w, 503, "temporarily_unavailable")
	}
}
