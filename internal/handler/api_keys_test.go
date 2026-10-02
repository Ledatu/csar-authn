package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
)

func TestAPICredentialPublicJSONNeverIncludesSecretOrOwner(t *testing.T) {
	key := store.APICredential{
		ID: uuid.New(), OwnerID: uuid.New(), SellerID: "123",
		TokenHash: strings.Repeat("a", 64), Prefix: "aurum_pat_12345678",
	}
	body, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{key.TokenHash, key.OwnerID.String()} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("credential JSON exposed secret or owner: %s", body)
		}
	}
	if !strings.Contains(string(body), key.Prefix) {
		t.Fatal("credential JSON should retain safe display prefix")
	}
}

func TestAPIKeyMutationOriginAndSellerValidation(t *testing.T) {
	if !apiKeyMutationOriginAllowed("https://seller.aurum-sky.net") ||
		apiKeyMutationOriginAllowed("https://evil.example") ||
		apiKeyMutationOriginAllowed("") {
		t.Fatal("API key mutation origin policy changed")
	}
	for _, seller := range []string{"", "0", "-1", "0012", "12x", "32709D54-A113-46F0-AC1C-FC418AB7D1AE"} {
		if validWBSellerID(seller) {
			t.Fatalf("accepted non-canonical seller ID %q", seller)
		}
	}
	if !validWBSellerID("32709d54-a113-46f0-ac1c-fc418ab7d1ae") {
		t.Fatal("valid seller ID rejected")
	}
}
