// Package mock provides an in-memory Store implementation for testing.
package mock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

// Store is a thread-safe in-memory implementation of store.Store.
type Store struct {
	mu                 sync.Mutex
	users              map[uuid.UUID]*store.User
	accounts           map[string]*store.OAuthAccount // key: provider|provider_user_id
	attributionTouches map[uuid.UUID]*store.AttributionTouch
	passkeys           map[uuid.UUID]*store.Passkey
	passkeyChallenges  map[uuid.UUID]*store.PasskeyChallenge
	serviceAccounts    map[string]*store.ServiceAccount // key: name
	sessions           map[string]*store.Session        // key: session ID
	mergeRecords       map[string]*store.MergeRecord    // key: token_hash
	botVerifications   map[uuid.UUID]*store.BotVerification
	emailOTPChallenges map[uuid.UUID]*store.EmailOTPChallenge
	loginHandoffs      map[uuid.UUID]*store.LoginHandoff
}

// New returns a new mock Store.
func New() *Store {
	return &Store{
		users:              make(map[uuid.UUID]*store.User),
		accounts:           make(map[string]*store.OAuthAccount),
		attributionTouches: make(map[uuid.UUID]*store.AttributionTouch),
		passkeys:           make(map[uuid.UUID]*store.Passkey),
		passkeyChallenges:  make(map[uuid.UUID]*store.PasskeyChallenge),
		serviceAccounts:    make(map[string]*store.ServiceAccount),
		emailOTPChallenges: make(map[uuid.UUID]*store.EmailOTPChallenge),
		loginHandoffs:      make(map[uuid.UUID]*store.LoginHandoff),
	}
}

func oauthKey(provider, providerUserID string) string {
	if provider == store.EmailProvider {
		providerUserID = strings.ToLower(providerUserID)
	}
	return provider + "|" + providerUserID
}

func (s *Store) GetUserByID(_ context.Context, id uuid.UUID) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

// followMergedLocked walks merged_into to the canonical user. Callers must hold s.mu.
func (s *Store) followMergedLocked(id uuid.UUID) (*store.User, bool) {
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	for hops := 0; u.MergedInto != nil && hops < 5; hops++ {
		next, ok := s.users[*u.MergedInto]
		if !ok {
			break
		}
		u = next
	}
	return u, true
}

func (s *Store) GetUsersByIDs(_ context.Context, ids []uuid.UUID) ([]store.ResolvedUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[uuid.UUID]struct{}, len(ids))
	var out []store.ResolvedUser
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		u, ok := s.followMergedLocked(id)
		if !ok {
			continue
		}
		out = append(out, store.ResolvedUser{User: *u, RequestedID: id})
	}
	return out, nil
}

func (s *Store) GetUsersByProviderIDs(_ context.Context, provider string, providerUserIDs []string) ([]store.ProviderUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]struct{}, len(providerUserIDs))
	var out []store.ProviderUser
	for _, pid := range providerUserIDs {
		if _, dup := seen[pid]; dup {
			continue
		}
		seen[pid] = struct{}{}
		acct, ok := s.accounts[oauthKey(provider, pid)]
		if !ok {
			continue
		}
		u, ok := s.followMergedLocked(acct.UserID)
		if !ok {
			continue
		}
		out = append(out, store.ProviderUser{
			User:             *u,
			ProviderUserID:   acct.ProviderUserID,
			ProviderMetadata: acct.ProviderMetadata,
		})
	}
	return out, nil
}

func (s *Store) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			cp := *u
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetUserByPhone(_ context.Context, phone string) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Phone == phone {
			cp := *u
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateUser(_ context.Context, u *store.User) (*store.User, error) {
	email, err := store.CanonicalizeUserEmail(u.Email)
	if err != nil {
		return nil, err
	}
	u.Email = email

	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	// Check email uniqueness.
	if u.Email != "" {
		for _, existing := range s.users {
			if strings.EqualFold(existing.Email, u.Email) {
				return nil, store.ErrUnverifiedEmailConflict
			}
		}
	}

	cp := *u
	s.users[u.ID] = &cp
	return u, nil
}

func (s *Store) SetUserPhoneIfEmpty(_ context.Context, userID uuid.UUID, phone string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	if strings.TrimSpace(phone) == "" || u.Phone != "" {
		return nil
	}
	u.Phone = phone
	u.UpdatedAt = time.Now()
	return nil
}

func (s *Store) UpdateUserProfile(_ context.Context, userID uuid.UUID, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	u.DisplayName = displayName
	u.UpdatedAt = time.Now()
	return nil
}

func (s *Store) UpdateUserAvatar(_ context.Context, userID uuid.UUID, avatar store.ManagedAvatar) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	u.AvatarStorageKey = avatar.DefaultStorageKey
	u.AvatarPreviewStorageKey = avatar.PreviewStorageKey
	u.AvatarMasterStorageKey = avatar.MasterStorageKey
	u.AvatarURL = ""
	u.UpdatedAt = time.Now()
	return nil
}

func (s *Store) GetOAuthAccount(_ context.Context, provider, providerUserID string) (*store.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[oauthKey(provider, providerUserID)]
	if !ok && provider == store.EmailProvider {
		for _, acct := range s.accounts {
			if acct.Provider == provider && strings.EqualFold(acct.ProviderUserID, providerUserID) {
				a = acct
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) GetOAuthAccountsByUserID(_ context.Context, userID uuid.UUID) ([]store.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.OAuthAccount
	for _, a := range s.accounts {
		if a.UserID == userID {
			out = append(out, *a)
		}
	}
	return out, nil
}

func (s *Store) CreateOAuthAccount(_ context.Context, acct *store.OAuthAccount) error {
	if err := store.CanonicalizeOAuthAccount(acct); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := oauthKey(acct.Provider, acct.ProviderUserID)
	if _, ok := s.accounts[key]; ok {
		return store.ErrProviderAlreadyLinked
	}
	now := time.Now()
	acct.LinkedAt = now
	acct.UpdatedAt = now
	cp := *acct
	s.accounts[key] = &cp
	return nil
}

func (s *Store) UpdateOAuthAccount(_ context.Context, acct *store.OAuthAccount) error {
	if err := store.CanonicalizeOAuthAccount(acct); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := oauthKey(acct.Provider, acct.ProviderUserID)
	if _, ok := s.accounts[key]; !ok {
		return store.ErrNotFound
	}
	acct.UpdatedAt = time.Now()
	cp := *acct
	s.accounts[key] = &cp
	return nil
}

func (s *Store) DeleteOAuthAccount(_ context.Context, provider string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loginMethods := 0
	for _, account := range s.accounts {
		if account.UserID == userID {
			loginMethods++
		}
	}
	for _, passkey := range s.passkeys {
		if passkey.UserID == userID {
			loginMethods++
		}
	}
	if loginMethods <= 1 {
		return store.ErrLastLoginMethod
	}
	for key, a := range s.accounts {
		if a.Provider == provider && a.UserID == userID {
			delete(s.accounts, key)
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) DeleteEmailOAuthAccount(_ context.Context, userID uuid.UUID, email string) error {
	email, err := store.NormalizeEmailString(email)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := oauthKey(store.EmailProvider, email)
	account, ok := s.accounts[key]
	if !ok || account.UserID != userID {
		return store.ErrNotFound
	}

	loginMethods := 0
	for _, account := range s.accounts {
		if account.UserID == userID {
			loginMethods++
		}
	}
	for _, passkey := range s.passkeys {
		if passkey.UserID == userID {
			loginMethods++
		}
	}
	if loginMethods <= 1 {
		return store.ErrLastLoginMethod
	}

	delete(s.accounts, key)

	user, ok := s.users[userID]
	if ok && strings.EqualFold(user.Email, email) {
		nextEmail := ""
		for _, account := range s.accounts {
			if account.UserID == userID && account.Provider == store.EmailProvider {
				nextEmail = account.ProviderUserID
				break
			}
		}
		user.Email = nextEmail
		user.UpdatedAt = time.Now()
	}

	return nil
}

// FindOrCreateUser mirrors the production matching priority:
//  1. Exact provider+providerUserID match
//  2. Verified email match
//  3. Verified phone match (even if unverified email conflicts)
//  4. Create new user
func (s *Store) FindOrCreateUser(ctx context.Context, acct *store.OAuthAccount, email, phone, displayName, avatarURL string) (*store.User, store.FindOrCreateResult, error) {
	if err := store.CanonicalizeOAuthAccount(acct); err != nil {
		return nil, 0, err
	}
	canonicalEmail, err := store.CanonicalizeUserEmail(email)
	if err != nil {
		return nil, 0, err
	}
	email = canonicalEmail

	// Step 1: existing oauth link.
	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		existing.AccessToken = acct.AccessToken
		existing.RefreshToken = acct.RefreshToken
		existing.ExpiresAt = acct.ExpiresAt
		existing.Email = acct.Email
		existing.DisplayName = acct.DisplayName
		existing.AvatarURL = acct.AvatarURL
		existing.EmailVerified = acct.EmailVerified
		_ = s.UpdateOAuthAccount(ctx, existing)
		user, _ := s.GetUserByID(ctx, existing.UserID)
		if user.Phone == "" && phone != "" {
			_ = s.SetUserPhoneIfEmpty(ctx, user.ID, phone)
			user.Phone = phone
		}
		return user, store.ResultExistingLogin, nil
	}

	// Step 2: email match (verified only).
	var unverifiedEmailConflict bool
	if email != "" {
		user, err := s.GetUserByEmail(ctx, email)
		if err == nil {
			if acct.EmailVerified {
				acct.UserID = user.ID
				_ = s.CreateOAuthAccount(ctx, acct)
				return user, store.ResultLinkedToExisting, nil
			}
			unverifiedEmailConflict = true
		}
	}

	// Step 3: phone match.
	if phone != "" {
		user, err := s.GetUserByPhone(ctx, phone)
		if err == nil {
			acct.UserID = user.ID
			_ = s.CreateOAuthAccount(ctx, acct)
			return user, store.ResultLinkedToExisting, nil
		}
	}

	if unverifiedEmailConflict {
		return nil, 0, store.ErrUnverifiedEmailConflict
	}

	// Step 4: create new user.
	newUser := &store.User{
		ID:          uuid.New(),
		Email:       email,
		Phone:       phone,
		DisplayName: displayName,
		AvatarURL:   avatarURL,
	}
	created, err := s.CreateUser(ctx, newUser)
	if err != nil {
		return nil, 0, err
	}
	acct.UserID = created.ID
	_ = s.CreateOAuthAccount(ctx, acct)
	return created, store.ResultCreatedNewUser, nil
}

func (s *Store) LinkOAuthAccount(ctx context.Context, userID uuid.UUID, acct *store.OAuthAccount) error {
	if err := store.CanonicalizeOAuthAccount(acct); err != nil {
		return err
	}

	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		if existing.UserID == userID {
			existing.AccessToken = acct.AccessToken
			existing.RefreshToken = acct.RefreshToken
			existing.ExpiresAt = acct.ExpiresAt
			existing.Email = acct.Email
			existing.DisplayName = acct.DisplayName
			existing.AvatarURL = acct.AvatarURL
			existing.EmailVerified = acct.EmailVerified
			return s.UpdateOAuthAccount(ctx, existing)
		}
		return store.ErrProviderAlreadyLinked
	}
	acct.UserID = userID
	return s.CreateOAuthAccount(ctx, acct)
}

func (s *Store) CountOAuthAccounts(_ context.Context, userID uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.accounts {
		if a.UserID == userID {
			n++
		}
	}
	return n, nil
}

func (s *Store) CreatePasskey(_ context.Context, passkey *store.Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if passkey.ID == uuid.Nil {
		passkey.ID = uuid.New()
	}
	for _, existing := range s.passkeys {
		if string(existing.CredentialID) == string(passkey.CredentialID) {
			return store.ErrPasskeyAlreadyLinked
		}
	}
	now := time.Now()
	passkey.CreatedAt = now
	passkey.UpdatedAt = now
	cp := *passkey
	s.passkeys[passkey.ID] = &cp
	return nil
}

func (s *Store) ListPasskeysByUserID(_ context.Context, userID uuid.UUID) ([]store.Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Passkey, 0)
	for _, passkey := range s.passkeys {
		if passkey.UserID == userID {
			cp := *passkey
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) GetPasskeyByCredentialID(_ context.Context, credentialID []byte) (*store.Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, passkey := range s.passkeys {
		if string(passkey.CredentialID) == string(credentialID) {
			cp := *passkey
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) DeletePasskey(_ context.Context, passkeyID, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loginMethods := 0
	for _, account := range s.accounts {
		if account.UserID == userID {
			loginMethods++
		}
	}
	for _, passkey := range s.passkeys {
		if passkey.UserID == userID {
			loginMethods++
		}
	}
	if loginMethods <= 1 {
		return store.ErrLastLoginMethod
	}
	passkey, ok := s.passkeys[passkeyID]
	if !ok || passkey.UserID != userID {
		return store.ErrNotFound
	}
	delete(s.passkeys, passkeyID)
	return nil
}

func (s *Store) UpdatePasskeyUsage(_ context.Context, passkeyID uuid.UUID, signCount uint32, backupState bool, userVerified bool, lastUsedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	passkey, ok := s.passkeys[passkeyID]
	if !ok {
		return store.ErrNotFound
	}
	passkey.SignCount = signCount
	passkey.BackupState = backupState
	passkey.UserVerified = userVerified
	passkey.LastUsedAt = &lastUsedAt
	passkey.UpdatedAt = time.Now()
	return nil
}

func (s *Store) CountUserLoginMethods(_ context.Context, userID uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, account := range s.accounts {
		if account.UserID == userID {
			count++
		}
	}
	for _, passkey := range s.passkeys {
		if passkey.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (s *Store) CreatePasskeyChallenge(_ context.Context, challenge *store.PasskeyChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if challenge.ID == uuid.Nil {
		challenge.ID = uuid.New()
	}
	if challenge.CreatedAt.IsZero() {
		challenge.CreatedAt = time.Now()
	}
	cp := *challenge
	s.passkeyChallenges[challenge.ID] = &cp
	return nil
}

func (s *Store) ConsumePasskeyChallenge(_ context.Context, id uuid.UUID, kind string) (*store.PasskeyChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.passkeyChallenges[id]
	if !ok || challenge.Kind != kind || challenge.ConsumedAt != nil || time.Now().After(challenge.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	challenge.ConsumedAt = &now
	cp := *challenge
	return &cp, nil
}

func (s *Store) CleanExpiredPasskeyChallenges(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int64
	now := time.Now()
	for id, challenge := range s.passkeyChallenges {
		if challenge.ConsumedAt != nil || now.After(challenge.ExpiresAt) {
			delete(s.passkeyChallenges, id)
			removed++
		}
	}
	return removed, nil
}

func (s *Store) ListActiveServiceAccounts(_ context.Context) ([]store.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.ServiceAccount
	for _, sa := range s.serviceAccounts {
		if sa.Status == "active" {
			out = append(out, *sa)
		}
	}
	return out, nil
}

func (s *Store) GetServiceAccount(_ context.Context, name string) (*store.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sa
	return &cp, nil
}

func (s *Store) CreateServiceAccount(_ context.Context, sa *store.ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.serviceAccounts[sa.Name]; ok {
		return store.ErrAlreadyExists
	}
	if sa.Status == "" {
		sa.Status = "active"
	}
	sa.CreatedAt = time.Now()
	cp := *sa
	s.serviceAccounts[sa.Name] = &cp
	return nil
}

func (s *Store) UpdateServiceAccountKey(_ context.Context, name, newPEM string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok || sa.Status != "active" {
		return store.ErrNotFound
	}
	sa.PublicKeyPEM = newPEM
	now := time.Now()
	sa.RotatedAt = &now
	return nil
}

func (s *Store) RevokeServiceAccount(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok || sa.Status != "active" {
		return store.ErrNotFound
	}
	sa.Status = "revoked"
	now := time.Now()
	sa.RevokedAt = &now
	return nil
}

// ---------------------------------------------------------------------------
// Session methods
// ---------------------------------------------------------------------------

func (s *Store) CreateSession(_ context.Context, sess *store.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]*store.Session)
	}
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *Store) GetSession(_ context.Context, sessionID string) (*store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *Store) TouchSession(_ context.Context, sessionID string, now time.Time, newExpiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return store.ErrNotFound
	}
	sess.LastSeenAt = now
	sess.ExpiresAt = newExpiresAt
	return nil
}

func (s *Store) RevokeSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	sess.RevokedAt = &now
	return nil
}

func (s *Store) RevokeAdminSession(_ context.Context, adminSessionID string) (*store.AdminSessionRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, sess := range s.sessions {
		if safeSessionID(sess.ID) != adminSessionID {
			continue
		}
		if sess.RevokedAt != nil || !now.Before(sess.ExpiresAt) {
			return nil, store.ErrNotFound
		}

		revokedAt := now
		sess.RevokedAt = &revokedAt

		email := ""
		if u, ok := s.users[sess.UserID]; ok {
			email = u.Email
		}

		cp := *sess
		return &store.AdminSessionRow{Session: cp, UserEmail: email}, nil
	}

	return nil, store.ErrNotFound
}

func (s *Store) RevokeUserSessions(_ context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
		}
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var n int64
	for id, sess := range s.sessions {
		if sess.RevokedAt != nil || now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) ListUserSessions(_ context.Context, userID uuid.UUID) ([]store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []store.Session
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil && now.Before(sess.ExpiresAt) {
			out = append(out, *sess)
		}
	}
	return out, nil
}

func (s *Store) ListAdminSessions(_ context.Context, params store.AdminSessionListParams) ([]store.AdminSessionRow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var rows []store.AdminSessionRow
	for _, sess := range s.sessions {
		if params.UserID != nil && sess.UserID != *params.UserID {
			continue
		}
		email := ""
		if u, ok := s.users[sess.UserID]; ok {
			email = u.Email
		}
		if params.Email != "" && !strings.Contains(strings.ToLower(email), strings.ToLower(params.Email)) {
			continue
		}

		switch params.Status {
		case "", "all":
		case "active":
			if sess.RevokedAt != nil || !now.Before(sess.ExpiresAt) {
				continue
			}
		case "revoked":
			if sess.RevokedAt == nil {
				continue
			}
		case "expired":
			if sess.RevokedAt != nil || now.Before(sess.ExpiresAt) {
				continue
			}
		}

		cp := *sess
		rows = append(rows, store.AdminSessionRow{Session: cp, UserEmail: email})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastSeenAt.After(rows[j].LastSeenAt)
	})
	start := params.Offset
	if start > len(rows) {
		return nil, false, nil
	}
	end := start + params.Limit + 1
	if end > len(rows) {
		end = len(rows)
	}
	page := rows[start:end]
	hasMore := len(page) > params.Limit
	if hasMore {
		page = page[:params.Limit]
	}
	return page, hasMore, nil
}

func (s *Store) SearchUsers(_ context.Context, params store.UserSearchParams) ([]store.UserSearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := strings.TrimSpace(strings.ToLower(params.Query))
	if params.Limit <= 0 || query == "" {
		return []store.UserSearchResult{}, nil
	}

	exactID := uuid.Nil
	hasExactID := false
	if parsed, err := uuid.Parse(query); err == nil {
		exactID = parsed
		hasExactID = true
	}

	type rankedUser struct {
		result store.UserSearchResult
		rank   int
	}

	ranked := make([]rankedUser, 0, len(s.users))
	for _, u := range s.users {
		if u.MergedInto != nil {
			continue
		}

		email := strings.ToLower(u.Email)
		displayName := strings.ToLower(u.DisplayName)
		idText := strings.ToLower(u.ID.String())

		rank, matched := userSearchRank(hasExactID, exactID, idText, email, displayName, query)
		if !matched {
			continue
		}

		ranked = append(ranked, rankedUser{
			result: store.UserSearchResult{
				ID:                      u.ID,
				Email:                   u.Email,
				DisplayName:             u.DisplayName,
				AvatarStorageKey:        u.AvatarStorageKey,
				AvatarPreviewStorageKey: u.AvatarPreviewStorageKey,
				AvatarURL:               u.AvatarURL,
			},
			rank: rank,
		})
	}

	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].rank != ranked[j].rank {
			return ranked[i].rank < ranked[j].rank
		}
		if ranked[i].result.DisplayName != ranked[j].result.DisplayName {
			return ranked[i].result.DisplayName < ranked[j].result.DisplayName
		}
		if ranked[i].result.Email != ranked[j].result.Email {
			return ranked[i].result.Email < ranked[j].result.Email
		}
		return ranked[i].result.ID.String() < ranked[j].result.ID.String()
	})

	if len(ranked) > params.Limit {
		ranked = ranked[:params.Limit]
	}

	out := make([]store.UserSearchResult, len(ranked))
	for i := range ranked {
		out[i] = ranked[i].result
	}
	return out, nil
}

func userSearchRank(hasExactID bool, exactID uuid.UUID, idText, email, displayName, query string) (int, bool) {
	switch {
	case hasExactID && exactID.String() == idText:
		return 0, true
	case email == query:
		return 1, true
	case displayName == query:
		return 2, true
	case strings.HasPrefix(email, query):
		return 3, true
	case strings.HasPrefix(displayName, query):
		return 4, true
	case strings.Contains(email, query):
		return 5, true
	case strings.Contains(displayName, query):
		return 6, true
	default:
		return 0, false
	}
}

func (s *Store) UpsertUserAttributionTouch(_ context.Context, touch *store.AttributionTouch) (*store.AttributionTouch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if touch.ID == uuid.Nil {
		touch.ID = uuid.New()
	}
	now := time.Now()
	if touch.TouchedAt.IsZero() {
		touch.TouchedAt = now
	}
	if touch.CreatedAt.IsZero() {
		touch.CreatedAt = now
	}
	touch.UpdatedAt = now

	for _, existing := range s.attributionTouches {
		if existing.UserID != touch.UserID || existing.ReplacedBy != nil || existing.ConsumedAt != nil || !now.Before(existing.ExpiresAt) {
			continue
		}
		if store.SameAttributionTouchSource(existing, touch) {
			existing.TouchedAt = touch.TouchedAt
			existing.ExpiresAt = touch.ExpiresAt
			existing.SourceMetadata = store.CloneAttributionMetadata(touch.SourceMetadata)
			existing.UpdatedAt = now
			cp := *existing
			cp.SourceMetadata = store.CloneAttributionMetadata(existing.SourceMetadata)
			return &cp, nil
		}
		replacedBy := touch.ID
		existing.ReplacedBy = &replacedBy
		existing.UpdatedAt = now
	}

	cp := *touch
	cp.SourceMetadata = store.CloneAttributionMetadata(touch.SourceMetadata)
	s.attributionTouches[cp.ID] = &cp
	return &cp, nil
}

func (s *Store) GetActiveUserAttributionTouch(_ context.Context, userID uuid.UUID) (*store.AttributionTouch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var latest *store.AttributionTouch
	for _, touch := range s.attributionTouches {
		if touch.UserID != userID || touch.ReplacedBy != nil || touch.ConsumedAt != nil || !now.Before(touch.ExpiresAt) {
			continue
		}
		if latest == nil || touch.TouchedAt.After(latest.TouchedAt) {
			latest = touch
		}
	}
	if latest == nil {
		return nil, store.ErrNotFound
	}
	cp := *latest
	cp.SourceMetadata = store.CloneAttributionMetadata(latest.SourceMetadata)
	return &cp, nil
}

func (s *Store) ConsumeUserAttributionTouch(_ context.Context, userID, touchID uuid.UUID) (*store.AttributionTouch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	touch, ok := s.attributionTouches[touchID]
	if !ok || touch.UserID != userID || touch.ReplacedBy != nil || touch.ConsumedAt != nil || !time.Now().Before(touch.ExpiresAt) {
		return nil, store.ErrAttributionUnavailable
	}
	now := time.Now()
	touch.ConsumedAt = &now
	touch.UpdatedAt = now
	cp := *touch
	cp.SourceMetadata = store.CloneAttributionMetadata(touch.SourceMetadata)
	return &cp, nil
}

// ---------------------------------------------------------------------------
// Account Merge methods
// ---------------------------------------------------------------------------

func (s *Store) CreateMergeRecord(_ context.Context, rec *store.MergeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mergeRecords == nil {
		s.mergeRecords = make(map[string]*store.MergeRecord)
	}
	cp := *rec
	s.mergeRecords[rec.TokenHash] = &cp
	return nil
}

func (s *Store) ConsumeMergeRecord(_ context.Context, tokenHash string, participantUser uuid.UUID) (*store.MergeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.mergeRecords[tokenHash]
	if !ok || rec.ConsumedAt != nil || time.Now().After(rec.ExpiresAt) ||
		(rec.TargetUser != participantUser && rec.SourceUser != participantUser) {
		return nil, store.ErrMergeTokenExpired
	}
	now := time.Now()
	rec.ConsumedAt = &now
	cp := *rec
	return &cp, nil
}

func (s *Store) MergeUsers(_ context.Context, targetID, sourceID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if targetID == sourceID {
		return store.ErrSelfMerge
	}
	source, ok := s.users[sourceID]
	if !ok {
		return store.ErrNotFound
	}
	if source.MergedInto != nil {
		return store.ErrUserAlreadyMerged
	}
	target, ok := s.users[targetID]
	if !ok {
		return store.ErrNotFound
	}

	// Move oauth accounts.
	for key, a := range s.accounts {
		if a.UserID == sourceID {
			a.UserID = targetID
			s.accounts[key] = a
		}
	}
	for key, passkey := range s.passkeys {
		if passkey.UserID == sourceID {
			passkey.UserID = targetID
			passkey.UpdatedAt = time.Now()
			s.passkeys[key] = passkey
		}
	}

	// Revoke source sessions.
	now := time.Now()
	for _, sess := range s.sessions {
		if sess.UserID == sourceID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
		}
	}

	// Smart profile merge: capture source values, clear unique fields on source,
	// then fill target gaps — mirrors the Postgres path.
	srcEmail, srcPhone := source.Email, source.Phone
	srcDisplayName, srcAvatarStorageKey, srcAvatarPreviewStorageKey, srcAvatarMasterStorageKey, srcAvatarURL := source.DisplayName, source.AvatarStorageKey, source.AvatarPreviewStorageKey, source.AvatarMasterStorageKey, source.AvatarURL

	source.Email = ""
	source.Phone = ""

	if target.Email == "" && srcEmail != "" {
		target.Email = srcEmail
	}
	if target.Phone == "" && srcPhone != "" {
		target.Phone = srcPhone
	}
	if target.DisplayName == "" && srcDisplayName != "" {
		target.DisplayName = srcDisplayName
	}
	if target.AvatarStorageKey == "" && srcAvatarStorageKey != "" {
		target.AvatarStorageKey = srcAvatarStorageKey
		target.AvatarPreviewStorageKey = srcAvatarPreviewStorageKey
		target.AvatarMasterStorageKey = srcAvatarMasterStorageKey
		target.AvatarURL = ""
	} else if target.AvatarURL == "" && srcAvatarURL != "" {
		target.AvatarURL = srcAvatarURL
	}
	target.UpdatedAt = now

	// Soft-delete source.
	source.MergedInto = &targetID
	source.MergedAt = &now

	return nil
}

func (s *Store) MarkMergeAuthzComplete(_ context.Context, recordID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.mergeRecords {
		if rec.ID == recordID {
			now := time.Now()
			rec.AuthzCompletedAt = &now
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) GetPendingAuthzMerges(_ context.Context) ([]store.MergeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []store.MergeRecord
	for _, rec := range s.mergeRecords {
		if rec.ConsumedAt != nil && rec.AuthzCompletedAt == nil {
			result = append(result, *rec)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Bot Verification methods
// ---------------------------------------------------------------------------

func (s *Store) CreateBotVerification(_ context.Context, v *store.BotVerification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.botVerifications == nil {
		s.botVerifications = make(map[uuid.UUID]*store.BotVerification)
	}
	cp := *v
	s.botVerifications[v.ID] = &cp
	return nil
}

func (s *Store) GetBotVerification(_ context.Context, id uuid.UUID) (*store.BotVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.botVerifications[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *v
	return &cp, nil
}

func (s *Store) ConfirmBotVerification(_ context.Context, codeHash, provider, providerUserID, displayName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, v := range s.botVerifications {
		if v.CodeHash == codeHash && v.Status == "pending" && now.Before(v.ExpiresAt) {
			v.Status = "confirmed"
			v.Provider = provider
			v.ProviderUserID = providerUserID
			v.ProviderDisplay = displayName
			v.ConfirmedAt = &now
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) ConsumeBotVerification(_ context.Context, id uuid.UUID) (*store.BotVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.botVerifications[id]
	if !ok || v.Status != "confirmed" || time.Now().After(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	v.Status = "consumed"
	v.ConsumedAt = &now
	cp := *v
	return &cp, nil
}

func (s *Store) CleanExpiredBotVerifications(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var n int64
	for _, v := range s.botVerifications {
		if (v.Status == "pending" || v.Status == "confirmed") && now.After(v.ExpiresAt) {
			v.Status = "expired"
			n++
		}
	}
	return n, nil
}

func (s *Store) CountPendingBotVerifications(_ context.Context, ipAddress string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, v := range s.botVerifications {
		if v.IPAddress == ipAddress && v.Status == "pending" && now.Before(v.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (s *Store) CreateEmailOTPChallenge(_ context.Context, challenge *store.EmailOTPChallenge) error {
	email, err := store.CanonicalizeUserEmail(challenge.Email)
	if err != nil {
		return err
	}
	challenge.Email = email

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emailOTPChallenges == nil {
		s.emailOTPChallenges = make(map[uuid.UUID]*store.EmailOTPChallenge)
	}
	cp := *challenge
	s.emailOTPChallenges[challenge.ID] = &cp
	return nil
}

func (s *Store) VerifyEmailOTPChallenge(_ context.Context, id uuid.UUID, codeHash string, maxAttempts int) (*store.EmailOTPChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.emailOTPChallenges[id]
	if !ok {
		return nil, store.ErrEmailOTPUnavailable
	}
	now := time.Now()
	if challenge.Status != "pending" || !now.Before(challenge.ExpiresAt) {
		if challenge.Status == "pending" {
			challenge.Status = "expired"
		}
		return nil, store.ErrEmailOTPUnavailable
	}
	if challenge.Attempts >= maxAttempts {
		return nil, store.ErrEmailOTPTooManyAttempts
	}
	if challenge.CodeHash != codeHash {
		challenge.Attempts++
		if challenge.Attempts >= maxAttempts {
			challenge.Status = "expired"
			return nil, store.ErrEmailOTPTooManyAttempts
		}
		return nil, store.ErrEmailOTPInvalidCode
	}
	challenge.Attempts++
	challenge.Status = "consumed"
	challenge.ConsumedAt = &now
	cp := *challenge
	return &cp, nil
}

func (s *Store) CountPendingEmailOTPChallengesByIP(_ context.Context, ipAddress string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, challenge := range s.emailOTPChallenges {
		if challenge.IPAddress == ipAddress && challenge.Status == "pending" && now.Before(challenge.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (s *Store) CountPendingEmailOTPChallengesByEmail(_ context.Context, email string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, challenge := range s.emailOTPChallenges {
		if strings.EqualFold(challenge.Email, email) && challenge.Status == "pending" && now.Before(challenge.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (s *Store) GetLatestEmailOTPChallengeByEmail(_ context.Context, email string) (*store.EmailOTPChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *store.EmailOTPChallenge
	for _, challenge := range s.emailOTPChallenges {
		if !strings.EqualFold(challenge.Email, email) {
			continue
		}
		if latest == nil || challenge.CreatedAt.After(latest.CreatedAt) {
			latest = challenge
		}
	}
	if latest == nil {
		return nil, store.ErrNotFound
	}
	cp := *latest
	return &cp, nil
}

func (s *Store) CleanExpiredEmailOTPChallenges(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var n int64
	for _, challenge := range s.emailOTPChallenges {
		if challenge.Status == "pending" && !now.Before(challenge.ExpiresAt) {
			challenge.Status = "expired"
			n++
		}
	}
	return n, nil
}

func (s *Store) CreateLoginHandoff(_ context.Context, handoff *store.LoginHandoff) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *handoff
	s.loginHandoffs[handoff.ID] = &cp
	return nil
}

func (s *Store) GetLoginHandoffByScanToken(_ context.Context, scanTokenHash string) (*store.LoginHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, handoff := range s.loginHandoffs {
		if handoff.ScanTokenHash == scanTokenHash {
			cp := *handoff
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetLoginHandoffStatusForDesktop(_ context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handoff, ok := s.loginHandoffs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *handoff
	return &cp, nil
}

func (s *Store) ApproveLoginHandoff(_ context.Context, id uuid.UUID, approvedByUserID uuid.UUID) (*store.LoginHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handoff, ok := s.loginHandoffs[id]
	if !ok || handoff.Status != "pending" || !time.Now().Before(handoff.ExpiresAt) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	now := time.Now()
	handoff.Status = "approved"
	handoff.ApprovedByUserID = &approvedByUserID
	handoff.ApprovedAt = &now
	cp := *handoff
	return &cp, nil
}

func (s *Store) DenyLoginHandoff(_ context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handoff, ok := s.loginHandoffs[id]
	if !ok || handoff.Status != "pending" || !time.Now().Before(handoff.ExpiresAt) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	now := time.Now()
	handoff.Status = "denied"
	handoff.DeniedAt = &now
	cp := *handoff
	return &cp, nil
}

func (s *Store) ConsumeApprovedLoginHandoff(_ context.Context, id uuid.UUID) (*store.LoginHandoff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handoff, ok := s.loginHandoffs[id]
	if !ok || handoff.Status != "approved" || !time.Now().Before(handoff.ExpiresAt) {
		return nil, store.ErrLoginHandoffUnavailable
	}
	now := time.Now()
	handoff.Status = "consumed"
	handoff.ConsumedAt = &now
	cp := *handoff
	return &cp, nil
}

func (s *Store) ExpireLoginHandoff(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	handoff, ok := s.loginHandoffs[id]
	if !ok {
		return store.ErrNotFound
	}
	if handoff.Status == "pending" {
		handoff.Status = "expired"
	}
	return nil
}

func (s *Store) CountPendingLoginHandoffs(_ context.Context, ipAddress string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, handoff := range s.loginHandoffs {
		if handoff.DesktopIPAddress == ipAddress && handoff.Status == "pending" && now.Before(handoff.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteInactiveLoginHandoffs(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var n int64
	for id, handoff := range s.loginHandoffs {
		if handoff.Status == "denied" || handoff.Status == "consumed" || handoff.Status == "expired" || !now.Before(handoff.ExpiresAt) {
			delete(s.loginHandoffs, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) MigrateTelegramID(_ context.Context, oldID, newID string, metadata map[string]interface{}) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldKey := oauthKey("telegram", oldID)
	newKey := oauthKey("telegram", newID)

	oldAcct, oldExists := s.accounts[oldKey]
	newAcct, newExists := s.accounts[newKey]

	if !oldExists {
		return false, nil
	}

	if newExists {
		if oldAcct.UserID == newAcct.UserID {
			delete(s.accounts, oldKey)
			if len(metadata) > 0 {
				newAcct.ProviderMetadata = metadata
				newAcct.UpdatedAt = time.Now()
			}
			return true, nil
		}
		return false, nil
	}

	delete(s.accounts, oldKey)
	oldAcct.ProviderUserID = newID
	oldAcct.UpdatedAt = time.Now()
	if len(metadata) > 0 {
		oldAcct.ProviderMetadata = metadata
	}
	cp := *oldAcct
	s.accounts[newKey] = &cp
	return true, nil
}

func (s *Store) Migrate(_ context.Context) error { return nil }
func (s *Store) Close() error                    { return nil }

// SeedUser inserts a pre-existing user for test setup.
func (s *Store) SeedUser(u *store.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	if email, err := store.CanonicalizeUserEmail(cp.Email); err == nil {
		cp.Email = email
	}
	s.users[u.ID] = &cp
}

func safeSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}
