package passkey

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-core/authnconfig"
)

func TestEncodeDecodeState(t *testing.T) {
	svc, err := New(config.PasskeyConfig{
		Enabled:          true,
		RPID:             "id.aurum-sky.net",
		RPDisplayName:    "AURUMSKYNET ID",
		Origins:          []string{"https://id.aurum-sky.net"},
		ChallengeTTL:     authnconfig.NewDuration(5 * time.Minute),
		StateCookieName:  "csar_passkey_state",
		UserVerification: "required",
		Attestation:      "none",
		StateSecret:      "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	challengeID := uuid.New()
	encoded, err := svc.EncodeState(challengeID, ChallengeKindLogin)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := svc.DecodeState(encoded, ChallengeKindLogin)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != challengeID {
		t.Fatalf("DecodeState() = %s, want %s", decoded, challengeID)
	}
}

func TestDecodeStateRejectsTampering(t *testing.T) {
	svc, err := New(config.PasskeyConfig{
		Enabled:          true,
		RPID:             "id.aurum-sky.net",
		RPDisplayName:    "AURUMSKYNET ID",
		Origins:          []string{"https://id.aurum-sky.net"},
		ChallengeTTL:     authnconfig.NewDuration(5 * time.Minute),
		StateCookieName:  "csar_passkey_state",
		UserVerification: "required",
		Attestation:      "none",
		StateSecret:      "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	challengeID := uuid.New()
	encoded, err := svc.EncodeState(challengeID, ChallengeKindRegistration)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DecodeState(encoded+"tampered", ChallengeKindRegistration); err == nil {
		t.Fatal("expected DecodeState to reject a tampered value")
	}
}
