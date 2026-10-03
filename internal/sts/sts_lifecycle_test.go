package sts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"errors"
	"fmt"
	"sync/atomic"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func generateEdDSAKeyPEM(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return pub, priv, string(pemBytes)
}

func setupLifecycleEnv(t *testing.T) (*Handler, *mock.Store, ed25519.PrivateKey) {
	t.Helper()

	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(authPub)

	kp := &session.KeyPair{
		PrivateKey: authPriv,
		PublicKey:  authPub,
		Algorithm:  "EdDSA",
		KID:        "test-kid",
		PublicDER:  pubDER,
	}
	jwtCfg := config.JWTConfig{
		Issuer:   testIssuer,
		Audience: "test-audience",
		TTL:      config.NewDuration(time.Hour),
	}
	mgr := session.NewManager(kp, jwtCfg)

	_, saPriv, saPEM := generateEdDSAKeyPEM(t)
	st := mock.New()

	sa := &store.ServiceAccount{
		Name:              "lifecycle-sa",
		PublicKeyPEM:      saPEM,
		AllowedAudiences:  []string{"aud-a"},
		AllowAllAudiences: false,
		TokenTTL:          15 * time.Minute,
		Status:            "active",
	}
	if err := st.CreateServiceAccount(context.Background(), sa); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	h, err := New(
		ctx, st,
		nil,
		5*time.Minute,
		time.Hour,
		testIssuer,
		mgr,
		NewMemoryReplayStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}

	return h, st, saPriv
}

func TestLifecycle_DBBackedSAWorks(t *testing.T) {
	h, _, saPriv := setupLifecycleEnv(t)

	c := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-1",
	}
	token := signJWT(t, saPriv, "EdDSA", c)
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {token},
		"audience":   {"aud-a"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_ReloadAppliesNewBootstrapAndRejectsDBCollision(t *testing.T) {
	h, _, _ := setupLifecycleEnv(t)
	firstPub, _, firstPEM := generateEdDSAKeyPEM(t)
	secondPub, _, secondPEM := generateEdDSAKeyPEM(t)
	bootstrap := []BootstrapAccount{{
		Name: "config-sa", PublicKeyPEM: firstPEM,
		AllowedAudiences: []string{"aud-a"}, TokenTTL: time.Hour,
	}}
	if err := h.ReloadWithBootstrap(context.Background(), bootstrap); err != nil {
		t.Fatal(err)
	}
	account, err := h.resolveAccount(context.Background(), "config-sa")
	if err != nil || !bytes.Equal(account.PublicKey.(ed25519.PublicKey), firstPub) {
		t.Fatalf("new config key not active: %v", err)
	}
	bootstrap[0].PublicKeyPEM = secondPEM
	if err := h.ReloadWithBootstrap(context.Background(), bootstrap); err != nil {
		t.Fatal(err)
	}
	account, err = h.resolveAccount(context.Background(), "config-sa")
	if err != nil || !bytes.Equal(account.PublicKey.(ed25519.PublicKey), secondPub) {
		t.Fatalf("updated config key not active: %v", err)
	}
	bootstrap = append(bootstrap, BootstrapAccount{
		Name: "lifecycle-sa", PublicKeyPEM: firstPEM,
		AllowedAudiences: []string{"aud-a"}, TokenTTL: time.Hour,
	})
	if err := h.ReloadWithBootstrap(context.Background(), bootstrap); err == nil {
		t.Fatal("new bootstrap entry must not shadow a database account")
	}
	account, err = h.resolveAccount(context.Background(), "config-sa")
	if err != nil || !bytes.Equal(account.PublicKey.(ed25519.PublicKey), secondPub) {
		t.Fatalf("failed reload changed previous config: %v", err)
	}
}

func TestLifecycle_RotateKeyRejectsOld(t *testing.T) {
	h, st, oldPriv := setupLifecycleEnv(t)

	_, newPriv, newPEM := generateEdDSAKeyPEM(t)

	if err := st.UpdateServiceAccountKey(context.Background(), "lifecycle-sa", newPEM); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Old key should be rejected.
	oldClaims := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-old",
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, oldPriv, "EdDSA", oldClaims)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("old key: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// New key should work.
	newClaims := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-new",
	}
	w = doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, newPriv, "EdDSA", newClaims)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("new key: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_RevokeRejectsExchange(t *testing.T) {
	h, st, saPriv := setupLifecycleEnv(t)

	if err := st.RevokeServiceAccount(context.Background(), "lifecycle-sa"); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	c := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-revoked",
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, saPriv, "EdDSA", c)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked SA: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

type countingLister struct {
	*mock.Store
	gets   atomic.Int64
	getErr error
}

func (c *countingLister) GetServiceAccount(ctx context.Context, name string) (*store.ServiceAccount, error) {
	c.gets.Add(1)
	if c.getErr != nil {
		return nil, c.getErr
	}
	return c.Store.GetServiceAccount(ctx, name)
}

func lazyClaims(iss, jti string) assertionClaims {
	return assertionClaims{
		Iss: iss,
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: jti,
	}
}

func exchange(t *testing.T, h *Handler, priv ed25519.PrivateKey, iss, jti, aud string) int {
	t.Helper()
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, priv, "EdDSA", lazyClaims(iss, jti))},
		"audience":   {aud},
	})
	if w.Code != http.StatusOK && w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected %d: %s", w.Code, w.Body.String())
	}
	return w.Code
}

func withCountingLister(t *testing.T, h *Handler) *countingLister {
	t.Helper()
	cl := &countingLister{Store: h.saLister.(*mock.Store)}
	h.saLister = cl
	return cl
}

func TestLifecycle_DBAccountReadOnEveryExchange(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)
	cl := withCountingLister(t, h)

	_, newPriv, newPEM := generateEdDSAKeyPEM(t)
	if err := st.CreateServiceAccount(context.Background(), &store.ServiceAccount{
		Name:             "new-sa",
		PublicKeyPEM:     newPEM,
		AllowedAudiences: []string{"aud-x"},
		Status:           "active",
	}); err != nil {
		t.Fatal(err)
	}

	if code := exchange(t, h, newPriv, "new-sa", "lazy-1", "aud-x"); code != http.StatusOK {
		t.Fatalf("miss should load from store: expected 200, got %d", code)
	}
	if code := exchange(t, h, newPriv, "new-sa", "lazy-2", "aud-x"); code != http.StatusOK {
		t.Fatalf("second exchange: expected 200, got %d", code)
	}
	if got := cl.gets.Load(); got != 2 {
		t.Errorf("expected one store read per exchange, got %d", got)
	}
}

func TestLifecycle_RevokedInStoreRejectedImmediately(t *testing.T) {
	h, st, saPriv := setupLifecycleEnv(t)

	if err := st.RevokeServiceAccount(context.Background(), "lifecycle-sa"); err != nil {
		t.Fatal(err)
	}

	if code := exchange(t, h, saPriv, "lifecycle-sa", "rv-1", "aud-a"); code != http.StatusUnauthorized {
		t.Fatalf("revoked SA must be rejected on next exchange: expected 401, got %d", code)
	}
}

func TestLifecycle_RotatedInStorePickedUpImmediately(t *testing.T) {
	h, st, oldPriv := setupLifecycleEnv(t)
	_, newPriv, newPEM := generateEdDSAKeyPEM(t)

	if err := st.UpdateServiceAccountKey(context.Background(), "lifecycle-sa", newPEM); err != nil {
		t.Fatal(err)
	}

	if code := exchange(t, h, oldPriv, "lifecycle-sa", "rot-old", "aud-a"); code != http.StatusUnauthorized {
		t.Errorf("old key: expected 401, got %d", code)
	}
	if code := exchange(t, h, newPriv, "lifecycle-sa", "rot-new", "aud-a"); code != http.StatusOK {
		t.Errorf("new key: expected 200, got %d", code)
	}
}

func TestLazyLoad_BootstrapWinsOverDBRow(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)

	_, bootPriv, bootPEM := generateEdDSAKeyPEM(t)
	_, dbPriv, dbPEM := generateEdDSAKeyPEM(t)
	if err := st.CreateServiceAccount(context.Background(), &store.ServiceAccount{
		Name:             "shared-sa",
		PublicKeyPEM:     dbPEM,
		AllowedAudiences: []string{"aud-db"},
		Status:           "active",
	}); err != nil {
		t.Fatal(err)
	}
	h.bootstrapAccounts = []BootstrapAccount{{
		Name:             "shared-sa",
		PublicKeyPEM:     bootPEM,
		AllowedAudiences: []string{"aud-boot"},
	}}
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	cl := withCountingLister(t, h)

	check := func(stage string) {
		t.Helper()
		if code := exchange(t, h, bootPriv, "shared-sa", stage+"-boot", "aud-boot"); code != http.StatusOK {
			t.Errorf("%s: bootstrap key expected 200, got %d", stage, code)
		}
		if code := exchange(t, h, dbPriv, "shared-sa", stage+"-db", "aud-db"); code != http.StatusUnauthorized {
			t.Errorf("%s: DB key must not override bootstrap: expected 401, got %d", stage, code)
		}
	}
	check("fresh")
	check("second")
	if got := cl.gets.Load(); got != 0 {
		t.Errorf("bootstrap entries must never be refreshed from the store, got %d reads", got)
	}
}

func TestLifecycle_UnknownNameIsNotCached(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)
	cl := withCountingLister(t, h)
	_, priv, pem := generateEdDSAKeyPEM(t)

	for i := 0; i < 3; i++ {
		if code := exchange(t, h, priv, "ghost-sa", fmt.Sprintf("neg-%d", i), "aud-x"); code != http.StatusUnauthorized {
			t.Fatalf("unknown SA: expected 401, got %d", code)
		}
	}
	if got := cl.gets.Load(); got != 3 {
		t.Fatalf("unknown issuer should hit the store on each request, got %d reads", got)
	}

	if err := st.CreateServiceAccount(context.Background(), &store.ServiceAccount{
		Name:             "ghost-sa",
		PublicKeyPEM:     pem,
		AllowedAudiences: []string{"aud-x"},
		Status:           "active",
	}); err != nil {
		t.Fatal(err)
	}
	if code := exchange(t, h, priv, "ghost-sa", "neg-created", "aud-x"); code != http.StatusOK {
		t.Fatalf("new SA must work on next exchange: expected 200, got %d", code)
	}
	if got := cl.gets.Load(); got != 4 {
		t.Errorf("expected 4 store reads, got %d", got)
	}
}

func TestLifecycle_NewAccountNeedsNoReload(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)
	_, priv, pem := generateEdDSAKeyPEM(t)

	if code := exchange(t, h, priv, "late-sa", "rl-1", "aud-x"); code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if err := st.CreateServiceAccount(context.Background(), &store.ServiceAccount{
		Name:             "late-sa",
		PublicKeyPEM:     pem,
		AllowedAudiences: []string{"aud-x"},
		Status:           "active",
	}); err != nil {
		t.Fatal(err)
	}
	if code := exchange(t, h, priv, "late-sa", "rl-2", "aud-x"); code != http.StatusOK {
		t.Fatalf("after create: expected 200, got %d", code)
	}
}

func TestLazyLoad_StoreErrorOnMissIs503(t *testing.T) {
	h, _, _ := setupLifecycleEnv(t)
	cl := withCountingLister(t, h)
	cl.getErr = errors.New("pg down")
	_, priv, _ := generateEdDSAKeyPEM(t)

	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, priv, "EdDSA", lazyClaims("any-sa", "err-1"))},
		"audience":   {"aud-x"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error on miss: expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_StoreErrorFailsClosedForCachedEntry(t *testing.T) {
	h, _, saPriv := setupLifecycleEnv(t)
	cl := withCountingLister(t, h)
	cl.getErr = errors.New("pg down")

	if code := exchange(t, h, saPriv, "lifecycle-sa", "stale-1", "aud-a"); code != http.StatusServiceUnavailable {
		t.Fatalf("database account must fail closed during outage: expected 503, got %d", code)
	}
}

func TestLifecycle_ReactivateUsesNewKeyAndAudienceWithoutReload(t *testing.T) {
	h, st, oldPriv := setupLifecycleEnv(t)
	if err := st.RevokeServiceAccount(context.Background(), "lifecycle-sa"); err != nil {
		t.Fatal(err)
	}
	_, newPriv, newPEM := generateEdDSAKeyPEM(t)
	reactivated, err := st.CreateOrReactivateServiceAccount(context.Background(), &store.ServiceAccount{
		Name: "lifecycle-sa", PublicKeyPEM: newPEM,
		AllowedAudiences: []string{"aud-b"}, TokenTTL: 15 * time.Minute,
	})
	if err != nil || !reactivated {
		t.Fatalf("reactivation failed: %v, %v", reactivated, err)
	}
	if code := exchange(t, h, oldPriv, "lifecycle-sa", "react-old", "aud-a"); code != http.StatusUnauthorized {
		t.Fatalf("old key should fail immediately: %d", code)
	}
	if code := exchange(t, h, newPriv, "lifecycle-sa", "react-new", "aud-b"); code != http.StatusOK {
		t.Fatalf("new key and audience should work immediately: %d", code)
	}
}

func TestLifecycle_EmptyAllowedAudienceNeverIssuesToken(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)
	_, priv, pemStr := generateEdDSAKeyPEM(t)
	if err := st.CreateServiceAccount(context.Background(), &store.ServiceAccount{
		Name: "empty-audience-sa", PublicKeyPEM: pemStr,
		AllowAllAudiences: true, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, priv, "EdDSA", lazyClaims("empty-audience-sa", "empty-aud"))},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("empty audience should be denied: %d %s", w.Code, w.Body.String())
	}
}
