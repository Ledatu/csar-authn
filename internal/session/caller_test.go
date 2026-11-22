package session

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/jwtx"
)

func TestHistoricalServiceNamesKeepSTSCompatibility(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(keys, config.JWTConfig{Issuer: "test"})
	for _, sub := range []string{"legacy worker", "старый-сервис", strings.Repeat("s", 257)} {
		token, err := m.IssueScopedToken(sub, []string{"owner-input"}, time.Minute)
		if err != nil {
			t.Fatal("new metadata broke legacy STS issuance", err)
		}
		verified, err := jwtx.VerifyWithKey(token, keys.PublicKey, &jwtx.VerifyConfig{RequiredIssuer: "test", RequiredAudience: "owner-input", AllowedAlgorithms: []string{"EdDSA"}})
		if err != nil || verified.Claims["sub"] != sub || verified.Claims["caller"] != nil {
			t.Fatal("legacy subject changed or acquired invalid caller metadata", err)
		}
	}
}

func TestSignedCallerMetadataAndLegacyCompatibility(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(keys, config.JWTConfig{Issuer: "test", Audience: "session", TTL: authnconfig.NewDuration(time.Hour)})
	token, err := m.IssueToken("user:1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.VerifyToken(token)
	if err != nil || claims.Caller == nil || claims.Caller.CallerKind != caller.Human || claims.Caller.CallerID != claims.Sub || claims.Caller.CredentialID != "" {
		t.Fatal("session token lost signed principal metadata", err)
	}
	sts, err := m.IssueScopedToken("svc:reporting", []string{"owner-input"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := jwtx.VerifyWithKey(sts, keys.PublicKey, &jwtx.VerifyConfig{RequiredIssuer: "test", RequiredAudience: "owner-input", AllowedAlgorithms: []string{"EdDSA"}})
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := verified.Claims["caller"].(map[string]any)
	if !ok || principal["caller_kind"] != "service" || principal["caller_id"] != "svc:reporting" || principal["effective_subject"] != "svc:reporting" {
		t.Fatal("STS principal was not signed")
	}
	if _, exists := principal["owner_subject"]; exists || verified.Claims["origin_caller"] != nil {
		t.Fatal("reusable service token acquired user/origin context")
	}
	legacyClaims := jwt.MapClaims{"sub": "user:1", "iss": "test", "aud": "session", "exp": time.Now().Add(time.Hour).Unix()}
	legacy, err := jwtx.Sign(keys, legacyClaims)
	if err != nil {
		t.Fatal(err)
	}
	old, err := m.VerifyToken(legacy)
	if err != nil || old.Caller != nil {
		t.Fatal("legacy token rejected or retrospectively classified", err)
	}
	legacyClaims["caller"] = &caller.Identity{Version: caller.Version, CallerKind: caller.Human, CallerID: "user:1", OwnerSubject: "user:1",
		EffectiveSubject: "foreign", CredentialKind: caller.Session, Assurance: caller.Verified}
	bad, err := jwtx.Sign(keys, legacyClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyToken(bad); err == nil {
		t.Fatal("caller metadata disagreed with authenticated subject")
	}
}
