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
	if updated.AvatarPreviewStorageKey != "" {
		t.Fatalf("avatar_preview_storage_key = %q, want empty", updated.AvatarPreviewStorageKey)
	}
	if updated.AvatarMasterStorageKey != "" {
		t.Fatalf("avatar_master_storage_key = %q, want empty", updated.AvatarMasterStorageKey)
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
		ID:                      uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		Email:                   "delete@test.com",
		DisplayName:             "Delete User",
		AvatarStorageKey:        "avatars/user-1/current.png",
		AvatarPreviewStorageKey: "avatars/user-1/current-preview.webp",
		AvatarMasterStorageKey:  "avatars/user-1/current-master.webp",
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
	if updated.AvatarPreviewStorageKey != "" {
		t.Fatalf("avatar_preview_storage_key = %q, want empty", updated.AvatarPreviewStorageKey)
	}
	if updated.AvatarMasterStorageKey != "" {
		t.Fatalf("avatar_master_storage_key = %q, want empty", updated.AvatarMasterStorageKey)
	}
	if len(deletedKeys) != 3 {
		t.Fatalf("deleted keys = %#v", deletedKeys)
	}
	wantDeleted := map[string]bool{
		"avatars/user-1/current.png":          true,
		"avatars/user-1/current-preview.webp": true,
		"avatars/user-1/current-master.webp":  true,
	}
	for _, key := range deletedKeys {
		if !wantDeleted[key] {
			t.Fatalf("unexpected deleted key %q in %#v", key, deletedKeys)
		}
		delete(wantDeleted, key)
	}
	if len(wantDeleted) != 0 {
		t.Fatalf("deleted keys = %#v", deletedKeys)
	}
}

func TestHandleAvatarUploadSetIntentReturnsUploadTargets(t *testing.T) {
	avatarClient := &mockAvatarClient{
		createUploadIntentFn: func(req avatar.UploadIntentRequest) (*avatar.UploadIntentResponse, error) {
			switch req.Filename {
			case "preview.webp":
				return &avatar.UploadIntentResponse{
					UploadToken: "intent-preview",
					Method:      "PUT",
					URL:         "https://upload.example.com/preview",
				}, nil
			case "default.webp":
				return &avatar.UploadIntentResponse{
					UploadToken: "intent-default",
					Method:      "PUT",
					URL:         "https://upload.example.com/default",
				}, nil
			case "master.webp":
				return &avatar.UploadIntentResponse{
					UploadToken: "intent-master",
					Method:      "PUT",
					URL:         "https://upload.example.com/master",
				}, nil
			default:
				t.Fatalf("unexpected filename %q", req.Filename)
				return nil, nil
			}
		},
	}
	h, st := newProfileHandler(t, avatarClient)
	user := &store.User{
		ID:          uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		Email:       "set-intent@test.com",
		DisplayName: "Variant Intent",
	}
	token := issueProfileBearer(t, h, st, user)

	req := httptest.NewRequest(http.MethodPost, "/auth/me/avatar/upload-set-intent", strings.NewReader(`{
		"assets":[
			{"kind":"preview","filename":"preview.webp","content_type":"image/webp","content_length":111},
			{"kind":"default","filename":"default.webp","content_type":"image/webp","content_length":222},
			{"kind":"master","filename":"master.webp","content_type":"image/webp","content_length":333}
		]
	}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleAvatarUploadSetIntent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		UploadToken string `json:"upload_token"`
		Assets      map[string]struct {
			URL string `json:"url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UploadToken == "" {
		t.Fatal("expected upload token")
	}
	if resp.Assets["preview"].URL != "https://upload.example.com/preview" {
		t.Fatalf("preview url = %q", resp.Assets["preview"].URL)
	}
	if resp.Assets["default"].URL != "https://upload.example.com/default" {
		t.Fatalf("default url = %q", resp.Assets["default"].URL)
	}
	if resp.Assets["master"].URL != "https://upload.example.com/master" {
		t.Fatalf("master url = %q", resp.Assets["master"].URL)
	}
}

func TestHandleFinalizeAvatarSetStoresVariantKeysAndReturnsPreviewURL(t *testing.T) {
	var deletedKeys []string
	avatarClient := &mockAvatarClient{
		finalizeAvatarFn: func(req avatar.FinalizeAvatarRequest) (*avatar.FinalizeAvatarResponse, error) {
			switch req.UploadToken {
			case "intent-preview":
				return &avatar.FinalizeAvatarResponse{
					StorageKey:  "avatars/user-1/new-preview.webp",
					ContentType: "image/webp",
				}, nil
			case "intent-default":
				return &avatar.FinalizeAvatarResponse{
					StorageKey:  "avatars/user-1/new-default.webp",
					ContentType: "image/webp",
				}, nil
			case "intent-master":
				return &avatar.FinalizeAvatarResponse{
					StorageKey:  "avatars/user-1/new-master.webp",
					ContentType: "image/webp",
				}, nil
			default:
				t.Fatalf("unexpected upload token %q", req.UploadToken)
				return nil, nil
			}
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
		ID:                      uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		Email:                   "set-finalize@test.com",
		DisplayName:             "Variant Finalize",
		AvatarStorageKey:        "avatars/user-1/old-default.webp",
		AvatarPreviewStorageKey: "avatars/user-1/old-preview.webp",
		AvatarMasterStorageKey:  "avatars/user-1/old-master.webp",
	}
	token := issueProfileBearer(t, h, st, user)

	uploadToken, err := h.issueAvatarUploadSetToken(user.ID.String(), map[string]string{
		avatarVariantPreview: "intent-preview",
		avatarVariantDefault: "intent-default",
		avatarVariantMaster:  "intent-master",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/me/avatar/finalize-set", strings.NewReader(`{"upload_token":"`+uploadToken+`"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.handleFinalizeAvatarSet(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := st.GetUserByID(req.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AvatarStorageKey != "avatars/user-1/new-default.webp" {
		t.Fatalf("avatar_storage_key = %q", updated.AvatarStorageKey)
	}
	if updated.AvatarPreviewStorageKey != "avatars/user-1/new-preview.webp" {
		t.Fatalf("avatar_preview_storage_key = %q", updated.AvatarPreviewStorageKey)
	}
	if updated.AvatarMasterStorageKey != "avatars/user-1/new-master.webp" {
		t.Fatalf("avatar_master_storage_key = %q", updated.AvatarMasterStorageKey)
	}
	if updated.AvatarURL != "" {
		t.Fatalf("avatar_url = %q, want empty", updated.AvatarURL)
	}

	var resp profileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AvatarURL != "https://signed.example.com/avatars/user-1/new-default.webp" {
		t.Fatalf("avatar_url = %q", resp.AvatarURL)
	}
	if resp.AvatarPreviewURL != "https://signed.example.com/avatars/user-1/new-preview.webp" {
		t.Fatalf("avatar_preview_url = %q", resp.AvatarPreviewURL)
	}

	wantDeleted := map[string]bool{
		"avatars/user-1/old-default.webp": true,
		"avatars/user-1/old-preview.webp": true,
		"avatars/user-1/old-master.webp":  true,
	}
	if len(deletedKeys) != len(wantDeleted) {
		t.Fatalf("deleted keys = %#v", deletedKeys)
	}
	for _, key := range deletedKeys {
		if !wantDeleted[key] {
			t.Fatalf("unexpected deleted key %q in %#v", key, deletedKeys)
		}
		delete(wantDeleted, key)
	}
	if len(wantDeleted) != 0 {
		t.Fatalf("missing deleted keys: %#v", wantDeleted)
	}
}
