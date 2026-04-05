package passkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/store"
)

const (
	ChallengeKindRegistration = "registration"
	ChallengeKindLogin        = "login"
)

type Service struct {
	webauthn     *webauthnlib.WebAuthn
	challengeTTL time.Duration
	stateCookie  string
	stateSecret  []byte
	verification protocol.UserVerificationRequirement
}

type LoginResult struct {
	User         *store.User
	Passkey      *store.Passkey
	SignCount    uint32
	BackupState  bool
	UserVerified bool
}

func New(cfg config.PasskeyConfig) (*Service, error) {
	verification, err := userVerification(cfg.UserVerification)
	if err != nil {
		return nil, err
	}
	attestation, err := conveyancePreference(cfg.Attestation)
	if err != nil {
		return nil, err
	}

	wa, err := webauthnlib.New(&webauthnlib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   verification,
		},
		AttestationPreference: attestation,
		Timeouts: webauthnlib.TimeoutsConfig{
			Login: webauthnlib.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.ChallengeTTL.Std(),
			},
			Registration: webauthnlib.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.ChallengeTTL.Std(),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create webauthn config: %w", err)
	}

	return &Service{
		webauthn:     wa,
		challengeTTL: cfg.ChallengeTTL.Std(),
		stateCookie:  cfg.StateCookieName,
		stateSecret:  []byte(cfg.StateSecret),
		verification: verification,
	}, nil
}

func (s *Service) StateCookieName() string {
	return s.stateCookie
}

func (s *Service) BeginRegistration(user *store.User, passkeys []store.Passkey) (*protocol.CredentialCreation, *store.PasskeyChallenge, error) {
	waUser := webauthnUser{
		user:        user,
		credentials: credentialsFromPasskeys(passkeys),
	}
	creation, session, err := s.webauthn.BeginRegistration(
		waUser,
		webauthnlib.WithExclusions(webauthnlib.Credentials(waUser.credentials).CredentialDescriptors()),
		webauthnlib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   s.verification,
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal registration session: %w", err)
	}
	userID := user.ID
	challenge := &store.PasskeyChallenge{
		ID:          uuid.New(),
		UserID:      &userID,
		Kind:        ChallengeKindRegistration,
		SessionData: data,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(s.challengeTTL),
	}
	return creation, challenge, nil
}

func (s *Service) FinishRegistration(user *store.User, existing []store.Passkey, challenge *store.PasskeyChallenge, response []byte, label string) (*store.Passkey, error) {
	session := &webauthnlib.SessionData{}
	if err := json.Unmarshal(challenge.SessionData, session); err != nil {
		return nil, fmt.Errorf("unmarshal registration session: %w", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, err
	}
	credential, err := s.webauthn.CreateCredential(webAuthnUser(user, existing), *session, parsed)
	if err != nil {
		return nil, err
	}
	passkey := passkeyFromCredential(user.ID, credential, label)
	return &passkey, nil
}

func (s *Service) BeginLogin() (*protocol.CredentialAssertion, *store.PasskeyChallenge, error) {
	assertion, session, err := s.webauthn.BeginDiscoverableLogin(
		webauthnlib.WithUserVerification(s.verification),
	)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal login session: %w", err)
	}
	challenge := &store.PasskeyChallenge{
		ID:          uuid.New(),
		Kind:        ChallengeKindLogin,
		SessionData: data,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(s.challengeTTL),
	}
	return assertion, challenge, nil
}

func (s *Service) FinishLogin(challenge *store.PasskeyChallenge, response []byte, lookup func(credentialID, userHandle []byte) (*store.User, *store.Passkey, error)) (*LoginResult, error) {
	session := &webauthnlib.SessionData{}
	if err := json.Unmarshal(challenge.SessionData, session); err != nil {
		return nil, fmt.Errorf("unmarshal login session: %w", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, err
	}

	var resolvedUser *store.User
	var resolvedPasskey *store.Passkey
	user, credential, err := s.webauthn.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthnlib.User, error) {
		u, passkey, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		resolvedPasskey = passkey
		return webauthnUser{
			user:        u,
			credentials: []webauthnlib.Credential{credentialFromPasskey(*passkey)},
		}, nil
	}, *session, parsed)
	if err != nil {
		return nil, err
	}
	_ = user
	if resolvedUser == nil || resolvedPasskey == nil {
		return nil, fmt.Errorf("passkey lookup resolved empty user")
	}
	return &LoginResult{
		User:         resolvedUser,
		Passkey:      resolvedPasskey,
		SignCount:    credential.Authenticator.SignCount,
		BackupState:  credential.Flags.BackupState,
		UserVerified: credential.Flags.UserVerified,
	}, nil
}

func (s *Service) EncodeState(id uuid.UUID, kind string) (string, error) {
	payload, err := json.Marshal(statePayload{
		ChallengeID: id.String(),
		Kind:        kind,
	})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.stateSecret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Service) DecodeState(value, expectedKind string) (uuid.UUID, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return uuid.Nil, fmt.Errorf("invalid passkey state")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return uuid.Nil, fmt.Errorf("decode passkey state payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return uuid.Nil, fmt.Errorf("decode passkey state signature: %w", err)
	}
	mac := hmac.New(sha256.New, s.stateSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return uuid.Nil, fmt.Errorf("invalid passkey state signature")
	}
	var state statePayload
	if err := json.Unmarshal(payload, &state); err != nil {
		return uuid.Nil, fmt.Errorf("unmarshal passkey state: %w", err)
	}
	if state.Kind != expectedKind {
		return uuid.Nil, fmt.Errorf("unexpected passkey state kind")
	}
	id, err := uuid.Parse(state.ChallengeID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse passkey state challenge id: %w", err)
	}
	return id, nil
}

type statePayload struct {
	ChallengeID string `json:"challenge_id"`
	Kind        string `json:"kind"`
}

type webauthnUser struct {
	user        *store.User
	credentials []webauthnlib.Credential
}

func webAuthnUser(user *store.User, passkeys []store.Passkey) webauthnUser {
	return webauthnUser{
		user:        user,
		credentials: credentialsFromPasskeys(passkeys),
	}
}

func (u webauthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID.String())
}

func (u webauthnUser) WebAuthnName() string {
	if u.user.Email != "" {
		return u.user.Email
	}
	return u.user.ID.String()
}

func (u webauthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.WebAuthnName()
}

func (u webauthnUser) WebAuthnCredentials() []webauthnlib.Credential {
	return u.credentials
}

func credentialsFromPasskeys(passkeys []store.Passkey) []webauthnlib.Credential {
	creds := make([]webauthnlib.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		creds = append(creds, credentialFromPasskey(passkey))
	}
	return creds
}

func credentialFromPasskey(passkey store.Passkey) webauthnlib.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(passkey.Transports))
	for _, transport := range passkey.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(transport))
	}
	flags := webauthnlib.CredentialFlags{
		UserPresent:    passkey.UserPresent,
		UserVerified:   passkey.UserVerified,
		BackupEligible: passkey.BackupEligible,
		BackupState:    passkey.BackupState,
	}
	return webauthnlib.Credential{
		ID:              passkey.CredentialID,
		PublicKey:       passkey.PublicKey,
		AttestationType: passkey.AttestationType,
		Transport:       transports,
		Flags:           flags,
		Authenticator: webauthnlib.Authenticator{
			AAGUID:     passkey.AAGUID,
			SignCount:  passkey.SignCount,
			Attachment: protocol.AuthenticatorAttachment(passkey.Attachment),
		},
		Attestation: webauthnlib.CredentialAttestation{
			ClientDataJSON:     passkey.AttestationClientDataJSON,
			ClientDataHash:     passkey.AttestationClientDataHash,
			AuthenticatorData:  passkey.AttestationAuthenticatorData,
			PublicKeyAlgorithm: passkey.AttestationPublicKeyAlgorithm,
			Object:             passkey.AttestationObject,
		},
	}
}

func passkeyFromCredential(userID uuid.UUID, credential *webauthnlib.Credential, label string) store.Passkey {
	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}
	now := time.Now().UTC()
	return store.Passkey{
		ID:                            uuid.New(),
		UserID:                        userID,
		Label:                         label,
		CredentialID:                  credential.ID,
		PublicKey:                     credential.PublicKey,
		AttestationType:               credential.AttestationType,
		Transports:                    transports,
		UserPresent:                   credential.Flags.UserPresent,
		UserVerified:                  credential.Flags.UserVerified,
		BackupEligible:                credential.Flags.BackupEligible,
		BackupState:                   credential.Flags.BackupState,
		AAGUID:                        credential.Authenticator.AAGUID,
		SignCount:                     credential.Authenticator.SignCount,
		Attachment:                    string(credential.Authenticator.Attachment),
		AttestationClientDataJSON:     credential.Attestation.ClientDataJSON,
		AttestationClientDataHash:     credential.Attestation.ClientDataHash,
		AttestationAuthenticatorData:  credential.Attestation.AuthenticatorData,
		AttestationObject:             credential.Attestation.Object,
		AttestationPublicKeyAlgorithm: credential.Attestation.PublicKeyAlgorithm,
		CreatedAt:                     now,
		UpdatedAt:                     now,
	}
}

func userVerification(value string) (protocol.UserVerificationRequirement, error) {
	switch value {
	case "", "required":
		return protocol.VerificationRequired, nil
	case "preferred":
		return protocol.VerificationPreferred, nil
	case "discouraged":
		return protocol.VerificationDiscouraged, nil
	default:
		return "", fmt.Errorf("unsupported user verification %q", value)
	}
}

func conveyancePreference(value string) (protocol.ConveyancePreference, error) {
	switch value {
	case "", "none":
		return protocol.PreferNoAttestation, nil
	case "indirect":
		return protocol.PreferIndirectAttestation, nil
	case "direct":
		return protocol.PreferDirectAttestation, nil
	case "enterprise":
		return protocol.PreferEnterpriseAttestation, nil
	default:
		return "", fmt.Errorf("unsupported attestation %q", value)
	}
}
