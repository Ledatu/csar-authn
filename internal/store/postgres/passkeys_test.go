package postgres

import (
	"testing"

	"github.com/ledatu/csar-authn/internal/store"
)

func TestNormalizePasskeyForStorage_FillsNonNullFields(t *testing.T) {
	passkey := &store.Passkey{}

	normalizePasskeyForStorage(passkey)

	byteFields := map[string][]byte{
		"CredentialID":                 passkey.CredentialID,
		"PublicKey":                    passkey.PublicKey,
		"AAGUID":                       passkey.AAGUID,
		"AttestationClientDataJSON":    passkey.AttestationClientDataJSON,
		"AttestationClientDataHash":    passkey.AttestationClientDataHash,
		"AttestationAuthenticatorData": passkey.AttestationAuthenticatorData,
		"AttestationObject":            passkey.AttestationObject,
	}
	for name, value := range byteFields {
		if value == nil {
			t.Fatalf("%s should be normalized to an empty slice", name)
		}
		if len(value) != 0 {
			t.Fatalf("%s length = %d, want 0", name, len(value))
		}
	}
	if passkey.Transports == nil {
		t.Fatal("Transports should be normalized to an empty slice")
	}
	if len(passkey.Transports) != 0 {
		t.Fatalf("Transports length = %d, want 0", len(passkey.Transports))
	}
}

func TestNormalizePasskeyForStorage_PreservesExistingValues(t *testing.T) {
	passkey := &store.Passkey{
		CredentialID:                 []byte{1},
		PublicKey:                    []byte{2},
		Transports:                   []string{"internal"},
		AAGUID:                       []byte{3},
		AttestationClientDataJSON:    []byte{4},
		AttestationClientDataHash:    []byte{5},
		AttestationAuthenticatorData: []byte{6},
		AttestationObject:            []byte{7},
	}

	normalizePasskeyForStorage(passkey)

	if len(passkey.CredentialID) != 1 || passkey.CredentialID[0] != 1 {
		t.Fatal("CredentialID should be preserved")
	}
	if len(passkey.PublicKey) != 1 || passkey.PublicKey[0] != 2 {
		t.Fatal("PublicKey should be preserved")
	}
	if len(passkey.Transports) != 1 || passkey.Transports[0] != "internal" {
		t.Fatal("Transports should be preserved")
	}
	if len(passkey.AAGUID) != 1 || passkey.AAGUID[0] != 3 {
		t.Fatal("AAGUID should be preserved")
	}
	if len(passkey.AttestationClientDataJSON) != 1 || passkey.AttestationClientDataJSON[0] != 4 {
		t.Fatal("AttestationClientDataJSON should be preserved")
	}
	if len(passkey.AttestationClientDataHash) != 1 || passkey.AttestationClientDataHash[0] != 5 {
		t.Fatal("AttestationClientDataHash should be preserved")
	}
	if len(passkey.AttestationAuthenticatorData) != 1 || passkey.AttestationAuthenticatorData[0] != 6 {
		t.Fatal("AttestationAuthenticatorData should be preserved")
	}
	if len(passkey.AttestationObject) != 1 || passkey.AttestationObject[0] != 7 {
		t.Fatal("AttestationObject should be preserved")
	}
}
