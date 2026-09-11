// Package sts implements the Security Token Service for service-to-service
// authentication. Service accounts exchange short-lived signed JWT assertions
// for scoped access tokens, following the jwt-bearer grant type (RFC 7523).
package sts

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/jwtx"
)

const (
	clockSkew = 30 * time.Second

	// DefaultAccountCacheTTL bounds how long a DB-backed service account is
	// served without re-reading its row, i.e. the worst-case propagation
	// delay of a revoke or key rotation to replicas that did not serve it.
	DefaultAccountCacheTTL = time.Minute

	// DefaultNegativeCacheTTL bounds how often an unknown or revoked issuer
	// name can trigger a store lookup.
	DefaultNegativeCacheTTL = 30 * time.Second
)

var errUnknownServiceAccount = errors.New("unknown service account")

// serviceAccount holds a loaded service account's public key and permissions.
type serviceAccount struct {
	PublicKey         crypto.PublicKey
	Algorithm         string          // detected from key type: "RS256" or "EdDSA"
	AllowedAudiences  map[string]bool // set of allowed audience strings
	AllowAllAudiences bool            // when true, omitting audience param returns all allowed
	TokenTTL          time.Duration   // 0 means use default

	// loadedAt is when the entry was read from the database. Zero marks a
	// config-backed entry, which is never refreshed or evicted by lookups.
	loadedAt time.Time
}

func (sa *serviceAccount) fromConfig() bool { return sa.loadedAt.IsZero() }

// ServiceAccountLister reads service accounts from the database.
type ServiceAccountLister interface {
	ListActiveServiceAccounts(ctx context.Context) ([]store.ServiceAccount, error)
	// GetServiceAccount returns a service account by name regardless of
	// status; store.ErrNotFound when no such row exists.
	GetServiceAccount(ctx context.Context, name string) (*store.ServiceAccount, error)
}

// BootstrapAccount mirrors authnconfig.BootstrapAccount without importing
// the config package directly so that sts stays config-schema-agnostic.
type BootstrapAccount struct {
	Name              string
	PublicKeyPEM      string
	AllowedAudiences  []string
	AllowAllAudiences bool
	TokenTTL          time.Duration
}

// Handler handles STS token exchange requests (POST /sts/token).
//
// Service accounts are cached in memory. Config-backed (bootstrap) entries
// are static and always win by name. DB-backed entries are loaded on first
// use and re-read from the store once older than accountCacheTTL, so
// creates, rotations and revokes made through any replica become visible on
// every replica without cross-replica propagation. Reload still rebuilds the
// whole cache eagerly for the replica that served an admin mutation and for
// config changes.
//
// Fields guarded by mu may be swapped at runtime via Reload without
// restarting the service.
type Handler struct {
	mu              sync.RWMutex
	accounts        map[string]*serviceAccount // keyed by SA name
	negative        map[string]time.Time       // unknown/revoked SA name -> expiry
	assertionMaxAge time.Duration

	saLister          ServiceAccountLister
	bootstrapAccounts []BootstrapAccount
	sessionMgr        *session.Manager
	replayStore       ReplayStore
	defaultTTL        time.Duration // from jwt.ttl
	issuer            string        // expected "aud" in incoming assertions
	accountCacheTTL   time.Duration
	negativeCacheTTL  time.Duration
	now               func() time.Time
	logger            *slog.Logger
}

// New creates an STS handler, loading service accounts from the database
// and merging in any bootstrap accounts from config (config wins by name).
// If replayStore is nil, a local in-memory replay store is used as fallback.
func New(ctx context.Context, saLister ServiceAccountLister, bootstrap []BootstrapAccount, assertionMaxAge, defaultTTL time.Duration, issuer string, sessionMgr *session.Manager, replayStore ReplayStore, logger *slog.Logger) (*Handler, error) {
	accounts, err := buildAccounts(ctx, saLister, bootstrap, time.Now(), logger)
	if err != nil {
		return nil, err
	}

	if replayStore == nil {
		replayStore = NewMemoryReplayStore()
		logger.Warn("STS using in-memory replay store; not suitable for multi-instance production")
	}

	return &Handler{
		accounts:          accounts,
		negative:          make(map[string]time.Time),
		assertionMaxAge:   assertionMaxAge,
		saLister:          saLister,
		bootstrapAccounts: bootstrap,
		sessionMgr:        sessionMgr,
		replayStore:       replayStore,
		defaultTTL:        defaultTTL,
		issuer:            issuer,
		accountCacheTTL:   DefaultAccountCacheTTL,
		negativeCacheTTL:  DefaultNegativeCacheTTL,
		now:               time.Now,
		logger:            logger,
	}, nil
}

// Reload atomically replaces service accounts from the database,
// re-merging bootstrap accounts from config (config wins by name), and
// drops the negative cache so a freshly created account is usable at once.
// On error the previous accounts remain active.
func (h *Handler) Reload(ctx context.Context) error {
	accounts, err := buildAccounts(ctx, h.saLister, h.bootstrapAccounts, h.clock(), h.logger)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.accounts = accounts
	h.negative = make(map[string]time.Time)
	h.mu.Unlock()
	return nil
}

// SetAssertionMaxAge updates the assertion max age (e.g. after config reload).
func (h *Handler) SetAssertionMaxAge(d time.Duration) {
	h.mu.Lock()
	h.assertionMaxAge = d
	h.mu.Unlock()
}

// SetCacheTTLs overrides how long DB-backed accounts are served before being
// re-read (account) and how long unknown/revoked names are remembered
// (negative). Non-positive values keep the current setting.
func (h *Handler) SetCacheTTLs(account, negative time.Duration) {
	h.mu.Lock()
	if account > 0 {
		h.accountCacheTTL = account
	}
	if negative > 0 {
		h.negativeCacheTTL = negative
	}
	h.mu.Unlock()
}

func (h *Handler) clock() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

// buildAccounts loads active service accounts from the database, then
// overlays bootstrap accounts from config. Config entries win by name.
func buildAccounts(ctx context.Context, lister ServiceAccountLister, bootstrap []BootstrapAccount, now time.Time, logger *slog.Logger) (map[string]*serviceAccount, error) {
	records, err := lister.ListActiveServiceAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing service accounts: %w", err)
	}

	accounts := make(map[string]*serviceAccount, len(records)+len(bootstrap))
	for _, rec := range records {
		sa, err := newServiceAccount(rec.PublicKeyPEM, rec.AllowedAudiences, rec.AllowAllAudiences, rec.TokenTTL, now)
		if err != nil {
			return nil, fmt.Errorf("SA %q: %w", rec.Name, err)
		}
		accounts[rec.Name] = sa
		logLoadedAccount(logger, rec.Name, "database", sa)
	}

	for _, ba := range bootstrap {
		sa, err := newServiceAccount(ba.PublicKeyPEM, ba.AllowedAudiences, ba.AllowAllAudiences, ba.TokenTTL, time.Time{})
		if err != nil {
			return nil, fmt.Errorf("bootstrap SA %q: %w", ba.Name, err)
		}
		accounts[ba.Name] = sa
		logLoadedAccount(logger, ba.Name, "config", sa)
	}

	return accounts, nil
}

func newServiceAccount(publicKeyPEM string, allowedAudiences []string, allowAll bool, tokenTTL time.Duration, loadedAt time.Time) (*serviceAccount, error) {
	pubKey, err := parsePublicKeyPEM([]byte(publicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("loading public key: %w", err)
	}
	alg, err := jwtx.DetectAlgorithm(pubKey)
	if err != nil {
		return nil, err
	}
	audSet := make(map[string]bool, len(allowedAudiences))
	for _, a := range allowedAudiences {
		audSet[a] = true
	}
	return &serviceAccount{
		PublicKey:         pubKey,
		Algorithm:         alg,
		AllowedAudiences:  audSet,
		AllowAllAudiences: allowAll,
		TokenTTL:          tokenTTL,
		loadedAt:          loadedAt,
	}, nil
}

func logLoadedAccount(logger *slog.Logger, name, source string, sa *serviceAccount) {
	audiences := make([]string, 0, len(sa.AllowedAudiences))
	for a := range sa.AllowedAudiences {
		audiences = append(audiences, a)
	}
	logger.Info("loaded STS service account",
		"name", name,
		"source", source,
		"algorithm", sa.Algorithm,
		"audiences", audiences,
	)
}

// resolveAccount returns the service account for name, reading the store on
// a cache miss or when a DB-backed entry is older than accountCacheTTL.
// Unknown, revoked and unparseable rows are evicted and negatively cached.
//
// A store failure never rejects a caller that has a cached entry: the stale
// entry keeps being served (revokes propagate once the store is back). With
// nothing cached the failure is returned so the caller can answer 503 —
// a 401 would make a store outage indistinguishable from a bad key to the
// client and could make it abandon a valid credential.
func (h *Handler) resolveAccount(ctx context.Context, name string) (*serviceAccount, error) {
	now := h.clock()

	h.mu.RLock()
	sa, cached := h.accounts[name]
	negativeUntil, negated := h.negative[name]
	accountCacheTTL := h.accountCacheTTL
	h.mu.RUnlock()

	if cached && (sa.fromConfig() || now.Sub(sa.loadedAt) < accountCacheTTL) {
		return sa, nil
	}
	if !cached && negated && now.Before(negativeUntil) {
		return nil, errUnknownServiceAccount
	}

	rec, err := h.saLister.GetServiceAccount(ctx, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		if cached {
			h.logger.Warn("service account refresh failed; serving cached entry", "sa", name, "error", err)
			return sa, nil
		}
		return nil, fmt.Errorf("loading service account %q: %w", name, err)
	}
	if err != nil || rec.Status != "active" {
		h.forget(name, now)
		return nil, errUnknownServiceAccount
	}

	fresh, err := newServiceAccount(rec.PublicKeyPEM, rec.AllowedAudiences, rec.AllowAllAudiences, rec.TokenTTL, now)
	if err != nil {
		h.logger.Error("service account row is unusable", "sa", name, "error", err)
		h.forget(name, now)
		return nil, errUnknownServiceAccount
	}

	h.mu.Lock()
	if existing, ok := h.accounts[name]; ok && existing.fromConfig() {
		fresh = existing
	} else {
		h.accounts[name] = fresh
	}
	delete(h.negative, name)
	h.mu.Unlock()

	if !cached {
		logLoadedAccount(h.logger, name, "database", fresh)
	}
	return fresh, nil
}

// forget evicts a DB-backed entry and remembers the name as unusable until
// now+negativeCacheTTL, dropping expired negative entries on the way so the
// map stays bounded by the rate of bogus issuers.
func (h *Handler) forget(name string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.accounts[name]; ok && !existing.fromConfig() {
		delete(h.accounts, name)
	}
	for n, until := range h.negative {
		if !until.After(now) {
			delete(h.negative, n)
		}
	}
	h.negative[name] = now.Add(h.negativeCacheTTL)
}

// ServeHTTP handles POST /sts/token requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	grantType := r.FormValue("grant_type")
	assertion := r.FormValue("assertion")
	audience := r.FormValue("audience")

	// Validate grant type.
	if grantType != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be urn:ietf:params:oauth:grant-type:jwt-bearer")
		return
	}

	if assertion == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "assertion is required")
		return
	}

	// Pre-parse assertion to extract issuer (SA name) before full verification.
	issuer, err := extractIssuer(assertion)
	if err != nil {
		h.logger.Warn("assertion parse failed", "error", err)
		writeError(w, http.StatusBadRequest, "invalid_grant", "invalid assertion")
		return
	}

	h.mu.RLock()
	assertionMaxAge := h.assertionMaxAge
	h.mu.RUnlock()

	sa, err := h.resolveAccount(r.Context(), issuer)
	if errors.Is(err, errUnknownServiceAccount) {
		h.logger.Warn("unknown service account", "sa", issuer)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "authentication failed")
		return
	}
	if err != nil {
		h.logger.Error("service account lookup failed", "sa", issuer, "error", err)
		writeError(w, http.StatusServiceUnavailable, "server_error", "service account lookup failed")
		return
	}

	// Parse and verify the full assertion.
	claims, err := parseAndVerifyAssertion(assertion, sa, h.issuer)
	if err != nil {
		h.logger.Warn("assertion verification failed", "sa", issuer, "error", err)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "authentication failed")
		return
	}

	// Require iat and enforce assertion lifetime bounds.
	if claims.Iat == 0 {
		writeError(w, http.StatusBadRequest, "invalid_grant", "iat claim is required")
		return
	}
	iatTime := time.Unix(claims.Iat, 0)
	if iatTime.After(time.Now().Add(clockSkew)) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion issued in the future")
		return
	}
	assertionAge := time.Since(iatTime)
	if assertionAge > assertionMaxAge+clockSkew {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "assertion too old")
		return
	}
	lifetime := time.Duration(claims.Exp-claims.Iat) * time.Second
	if lifetime <= 0 || lifetime > assertionMaxAge {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion lifetime out of bounds")
		return
	}
	maxExp := time.Now().Add(assertionMaxAge + clockSkew)
	if time.Unix(claims.Exp, 0).After(maxExp) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion exp too far in the future")
		return
	}

	// Require JTI for replay protection.
	if claims.Jti == "" {
		writeError(w, http.StatusBadRequest, "invalid_grant", "jti claim is required")
		return
	}

	replayed, err := h.replayStore.CheckAndRecord(r.Context(), claims.Iss, claims.Jti, time.Unix(claims.Exp, 0))
	if err != nil {
		h.logger.Error("replay store check failed", "sa", issuer, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "replay check failed")
		return
	}
	if replayed {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "assertion already used")
		return
	}

	// Resolve audiences.
	var audiences []string
	if audience != "" {
		// Validate requested audience against SA's allowed audiences.
		if !sa.AllowedAudiences[audience] {
			writeError(w, http.StatusForbidden, "access_denied", "audience not allowed")
			return
		}
		audiences = []string{audience}
	} else if sa.AllowAllAudiences {
		// SA explicitly opts in to receiving all allowed audiences when none requested.
		audiences = make([]string, 0, len(sa.AllowedAudiences))
		for a := range sa.AllowedAudiences {
			audiences = append(audiences, a)
		}
	} else {
		writeError(w, http.StatusBadRequest, "invalid_request", "audience parameter is required")
		return
	}

	// Determine TTL: SA-specific or global default.
	ttl := h.defaultTTL
	if sa.TokenTTL > 0 {
		ttl = sa.TokenTTL
	}

	// Issue the scoped access token.
	token, err := h.sessionMgr.IssueScopedToken(issuer, audiences, ttl)
	if err != nil {
		h.logger.Error("failed to issue STS token", "sa", issuer, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	h.logger.Info("STS token issued",
		"sa", issuer,
		"audiences", audiences,
		"ttl", ttl.String(),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
	})
}

// ---------------------------------------------------------------------------
// Public key loading
// ---------------------------------------------------------------------------

// parsePublicKeyPEM decodes a PEM-encoded PKIX public key.
func parsePublicKeyPEM(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// JWT assertion parsing and verification
// ---------------------------------------------------------------------------

type assertionHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type assertionClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

func extractIssuer(tokenStr string) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parsing claims: %w", err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("iss claim is required")
	}
	return c.Iss, nil
}

func parseAndVerifyAssertion(tokenStr string, sa *serviceAccount, expectedAud string) (*assertionClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header assertionHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}
	if header.Alg != sa.Algorithm {
		return nil, fmt.Errorf("algorithm mismatch: header %q, expected %q", header.Alg, sa.Algorithm)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if err := jwtx.VerifyWithKeyRaw(signingInput, sigBytes, sa.PublicKey, sa.Algorithm); err != nil {
		return nil, fmt.Errorf("assertion signature invalid: %w", err)
	}

	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(clockSkew)) {
		return nil, fmt.Errorf("assertion expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-clockSkew)) {
		return nil, fmt.Errorf("assertion not yet valid (nbf)")
	}
	if claims.Aud != expectedAud {
		return nil, fmt.Errorf("audience mismatch: got %q, expected %q", claims.Aud, expectedAud)
	}

	return &claims, nil
}

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

// tokenResponse is the successful STS token exchange response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // always "Bearer"
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// errorResponse matches RFC 6749 section 5.2.
type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error:       errCode,
		Description: description,
	})
}
