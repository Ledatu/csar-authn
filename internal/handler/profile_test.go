package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/avatar"
	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
)

type mockAvatarClient struct {
	createUploadIntentFn func(req avatar.UploadIntentRequest) (*avatar.UploadIntentResponse, error)
	finalizeAvatarFn     func(req avatar.FinalizeAvatarRequest) (*avatar.FinalizeAvatarResponse, error)
	deleteObjectFn       func(storageKey string) error
	signedReadURLFn      func(storageKey string) (string, error)
}

func (m *mockAvatarClient) CreateUploadIntent(_ context.Context, req avatar.UploadIntentRequest) (*avatar.UploadIntentResponse, error) {
	if m.createUploadIntentFn == nil {
		return &avatar.UploadIntentResponse{}, nil
	}
	return m.createUploadIntentFn(req)
}

func (m *mockAvatarClient) FinalizeAvatar(_ context.Context, req avatar.FinalizeAvatarRequest) (*avatar.FinalizeAvatarResponse, error) {
	if m.finalizeAvatarFn == nil {
		return &avatar.FinalizeAvatarResponse{}, nil
	}
	return m.finalizeAvatarFn(req)
}

func (m *mockAvatarClient) DeleteObject(_ context.Context, storageKey string) error {
	if m.deleteObjectFn == nil {
		return nil
	}
	return m.deleteObjectFn(storageKey)
}

func (m *mockAvatarClient) SignedReadURL(_ context.Context, storageKey string) (string, error) {
	if m.signedReadURLFn == nil {
		return "", nil
	}
	return m.signedReadURLFn(storageKey)
}

func newProfileHandler(t *testing.T, avatarClient avatarService) (*Handler, *mock.Store) {
	t.Helper()

	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager(kp, config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	})

	st := mock.New()
	h := &Handler{
		store:        st,
		sessionMgr:   sm,
		avatarClient: avatarClient,
		logger:       slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	return h, st
}

func issueProfileBearer(t *testing.T, h *Handler, st *mock.Store, user *store.User) string {
	t.Helper()

	st.SeedUser(user)
	token, err := h.sessionMgr.IssueToken(user.ID.String(), user.Email, user.DisplayName)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestHandleUpdateProfileSuccess(t *testing.T) {
	h, st := newProfileHandler(t, nil)
	user := &store.User{
		ID:          uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		Email:       "profile@test.com",
		DisplayName: "Old Name",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodPatch, "/auth/me/profile", strings.NewReader(`{"display_name":"New Name"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleUpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := st.GetUserByID(req.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "New Name" {
		t.Fatalf("display_name = %q, want %q", updated.DisplayName, "New Name")
	}

	var resp profileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DisplayName != "New Name" {
		t.Fatalf("response display_name = %q, want %q", resp.DisplayName, "New Name")
	}
}

func TestHandleUpdateProfileRejectsReadOnlyFields(t *testing.T) {
	h, st := newProfileHandler(t, nil)
	user := &store.User{
		ID:          uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Email:       "readonly@test.com",
		DisplayName: "Original",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodPatch, "/auth/me/profile", strings.NewReader(`{"display_name":"Changed","email":"new@example.com"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleUpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := st.GetUserByID(req.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("display_name changed to %q", stored.DisplayName)
	}
}

func TestHandleAvatarUploadIntentReturnsUploadTarget(t *testing.T) {
	avatarClient := &mockAvatarClient{
		createUploadIntentFn: func(req avatar.UploadIntentRequest) (*avatar.UploadIntentResponse, error) {
			if req.UserID != "55555555-5555-4555-8555-555555555555" {
				t.Fatalf("user_id = %q", req.UserID)
			}
			if req.ContentType != "image/png" {
				t.Fatalf("content_type = %q", req.ContentType)
			}
			if req.ContentLength != 42 {
				t.Fatalf("content_length = %d", req.ContentLength)
			}
			if req.Filename != "avatar.png" {
				t.Fatalf("filename = %q", req.Filename)
			}
			return &avatar.UploadIntentResponse{
				UploadToken: "upload-token",
				Method:      "PUT",
				URL:         "https://upload.example.com/avatar",
				Headers: map[string]string{
					"Content-Type": "image/png",
				},
			}, nil
		},
	}
	h, st := newProfileHandler(t, avatarClient)
	user := &store.User{
		ID:          uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		Email:       "intent@test.com",
		DisplayName: "Intent User",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodPost, "/auth/me/avatar/upload-intent", strings.NewReader(`{"filename":"avatar.png","content_type":"image/png","content_length":42}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleAvatarUploadIntent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		UploadToken string            `json:"upload_token"`
		Method      string            `json:"method"`
		URL         string            `json:"url"`
		Headers     map[string]string `json:"headers"`
		ObjectKey   string            `json:"object_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UploadToken != "upload-token" {
		t.Fatalf("upload_token = %q", resp.UploadToken)
	}
	if resp.URL != "https://upload.example.com/avatar" {
		t.Fatalf("url = %q", resp.URL)
	}
	if resp.ObjectKey != "" {
		t.Fatalf("object_key = %q, want empty", resp.ObjectKey)
	}
}

func TestHandleFinalizeAvatarStoresStorageKeyAndReturnsSignedURL(t *testing.T) {
	var deletedKeys []string
	avatarClient := &mockAvatarClient{
		finalizeAvatarFn: func(req avatar.FinalizeAvatarRequest) (*avatar.FinalizeAvatarResponse, error) {
			if req.UploadToken != "upload-token" {
				t.Fatalf("upload token = %q", req.UploadToken)
			}
			return &avatar.FinalizeAvatarResponse{
				StorageKey:  "avatars/user-1/new.png",
				ContentType: "image/png",
			}, nil
		},
		deleteObjectFn: func(storageKey string) error {
			deletedKeys = append(deletedKeys, storageKey)
			return nil
		},
		signedReadURLFn: func(storageKey string) (string, error) {
			return "https://signed.example.com/" + storageKey, nil
		},
	}
	h, st := newProfileHandler(t, avatarClient)
	user := &store.User{
		ID:               uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Email:            "avatar@test.com",
		DisplayName:      "Avatar User",
		AvatarStorageKey: "avatars/user-1/old.png",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodPost, "/auth/me/avatar", strings.NewReader(`{"upload_token":"upload-token"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleFinalizeAvatar(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := st.GetUserByID(req.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AvatarStorageKey != "avatars/user-1/new.png" {
		t.Fatalf("avatar_storage_key = %q", updated.AvatarStorageKey)
	}
	if updated.AvatarURL != "" {
		t.Fatalf("avatar_url = %q, want empty", updated.AvatarURL)
	}
	if len(deletedKeys) != 1 || deletedKeys[0] != "avatars/user-1/old.png" {
		t.Fatalf("deleted keys = %#v", deletedKeys)
	}

	var resp profileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AvatarURL != "https://signed.example.com/avatars/user-1/new.png" {
		t.Fatalf("avatar_url = %q", resp.AvatarURL)
	}
}

func TestHandleDeleteAvatarClearsStorageKey(t *testing.T) {
	var deletedKeys []string
	avatarClient := &mockAvatarClient{
		deleteObjectFn: func(storageKey string) error {
			deletedKeys = append(deletedKeys, storageKey)
			return nil
		},
	}
	h, st := newProfileHandler(t, avatarClient)
	user := &store.User{
		ID:               uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		Email:            "delete@test.com",
		DisplayName:      "Delete User",
		AvatarStorageKey: "avatars/user-1/current.png",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodDelete, "/auth/me/avatar", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleDeleteAvatar(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := st.GetUserByID(req.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AvatarStorageKey != "" {
		t.Fatalf("avatar_storage_key = %q, want empty", updated.AvatarStorageKey)
	}
	if len(deletedKeys) != 1 || deletedKeys[0] != "avatars/user-1/current.png" {
		t.Fatalf("deleted keys = %#v", deletedKeys)
	}
}
