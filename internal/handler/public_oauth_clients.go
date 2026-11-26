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

var errOAuthClientUnavailable = errors.New("OAuth client metadata unavailable")

type publicOAuthClients struct {
	store   store.OAuthClientStore
	cache   *redis.Client
	http    *http.Client
	limiter *usagebudget.Limiter
	locker  lock.Locker
	flight  singleflight.Group
	slots   chan struct{}
}

func (d *publicOAuthClients) admit(ctx context.Context, policy, peer string, capacity int64, window time.Duration) error {
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

func (d *publicOAuthClients) cached(ctx context.Context, key, id string) (store.OAuthClient, bool, error) {
	var c store.OAuthClient
	raw, err := d.cache.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return c, false, nil
	}
	if err != nil || len(raw) > 65536 {
		return c, false, errOAuthClientUnavailable
	}
	parsed, err := decodeOAuthClient(raw, id)
	if err != nil {
		return c, false, errOAuthClientUnavailable
	}
	return parsed, true, nil
}

func (d *publicOAuthClients) resolve(ctx context.Context, id string) (store.OAuthClient, error) {
	if strings.HasPrefix(id, "dcr_") {
		return d.store.OAuthClient(ctx, id)
	}
	if !validOAuthMetadataURL(id) {
		return store.OAuthClient{}, errOAuthClientMetadata
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
			return nil, errOAuthClientUnavailable
		}
		if c, ok, err := d.cached(fetchCtx, key, id); err != nil || ok {
			return c, err
		}
		release, err := d.locker.Acquire(fetchCtx, key+":fetch", 5*time.Second)
		if err != nil {
			for range 5 {
				select {
				case <-fetchCtx.Done():
					return nil, errOAuthClientUnavailable
				case <-time.After(100 * time.Millisecond):
				}
				if c, ok, err := d.cached(fetchCtx, key, id); err != nil || ok {
					return c, err
				}
			}
			return nil, errOAuthClientUnavailable
		}
		defer func() { _ = release() }()
		if err := d.admit(fetchCtx, "mcp.metadata.fetch", hashValue(id), 120, time.Hour); err != nil {
			return nil, err
		}
		return d.fetch(fetchCtx, key, id)
	})
	select {
	case <-ctx.Done():
		return store.OAuthClient{}, ctx.Err()
	case result := <-result:
		if result.Err != nil {
			return store.OAuthClient{}, result.Err
		}
		c, ok := result.Val.(store.OAuthClient)
		if !ok {
			return c, errOAuthClientUnavailable
		}
		// Return owned slices to each waiter.
		c.RedirectURIs = slices.Clone(c.RedirectURIs)
		c.GrantTypes = slices.Clone(c.GrantTypes)
		c.ResponseTypes = slices.Clone(c.ResponseTypes)
		return c, nil
	}
}

func (d *publicOAuthClients) fetch(ctx context.Context, key, id string) (store.OAuthClient, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return store.OAuthClient{}, errOAuthClientMetadata
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		if errors.Is(err, clientx.ErrNonPublicDestination) {
			return store.OAuthClient{}, errOAuthClientMetadata
		}
		return store.OAuthClient{}, errOAuthClientUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
		return store.OAuthClient{}, errOAuthClientUnavailable
	}
	if resp.StatusCode != http.StatusOK || media != "application/json" && (!strings.HasPrefix(media, "application/") || !strings.HasSuffix(media, "+json")) {
		return store.OAuthClient{}, errOAuthClientMetadata
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return store.OAuthClient{}, errOAuthClientUnavailable
	}
	c, err := decodeOAuthClient(raw, id)
	if err != nil {
		return c, err
	}
	if ttl := publicMetadataTTL(resp.Header, time.Now()); ttl > 0 {
		// Store only validated, normalized metadata; errors and malformed documents
		// are never cached. Throttling bounds repeated failures independently.
		encoded, err := json.Marshal(c)
		if err != nil || d.cache.Set(ctx, key, encoded, ttl).Err() != nil {
			return c, errOAuthClientUnavailable
		}
	}
	return c, nil
}

func publicMetadataTTL(header http.Header, now time.Time) time.Duration {
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

func (d *publicOAuthClients) registerClient(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := d.admit(r.Context(), "mcp.registration", requestPeer(r), 100, time.Hour); err != nil {
		publicClientError(w, err)
		return
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	raw, err := io.ReadAll(r.Body)
	if err != nil || media != "application/json" {
		oauthError(w, 400, "invalid_client_metadata")
		return
	}
	c, err := decodeOAuthClient(raw, "")
	if err != nil {
		oauthError(w, 400, "invalid_client_metadata")
		return
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		publicClientError(w, err)
		return
	}
	c.ClientID, c.IssuedAt = "dcr_"+randomToken(), time.Now().Unix()
	c, err = d.store.RegisterOAuthClient(r.Context(), c, hashValue(string(canonical)), 4096)
	if err != nil {
		publicClientError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func publicClientError(w http.ResponseWriter, err error) {
	var exceeded *usagebudget.Exceeded
	switch {
	case errors.As(err, &exceeded):
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(exceeded.RetryAfter.Seconds())+1)))
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable")
	case errors.Is(err, errOAuthClientMetadata), errors.Is(err, store.ErrNotFound):
		oauthError(w, 400, "invalid_client")
	default:
		oauthError(w, 503, "temporarily_unavailable")
	}
}
