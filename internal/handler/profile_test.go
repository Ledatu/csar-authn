package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
)

func newProfileHandler(t *testing.T) (*Handler, *mock.Store) {
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
		store:      st,
		sessionMgr: sm,
		logger:     slog.Default(),
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
	h, st := newProfileHandler(t)
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
	h, st := newProfileHandler(t)
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

func TestAvatarAPIIsRetired(t *testing.T) {
	h, _ := newProfileHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	for _, path := range []string{"/auth/me/avatar", "/auth/me/avatar/upload-intent", "/auth/me/avatar/upload-set-intent", "/auth/me/avatar/set"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
			if pattern != "" {
				t.Errorf("retired avatar route still registered: %s %s (%s)", method, path, pattern)
			}
		}
	}
}

func TestProfileDoesNotAcceptOrReturnAvatarFields(t *testing.T) {
	h, st := newProfileHandler(t)
	user := &store.User{ID: uuid.New(), DisplayName: "Identity"}
	token := issueProfileBearer(t, h, st, user)
	req := httptest.NewRequest(http.MethodPatch, "/auth/me/profile", strings.NewReader(`{"display_name":"Changed","avatar_url":"https://photo.invalid/a.jpg"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleUpdateProfile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("retired profile field accepted: %d %s", w.Code, w.Body.String())
	}
	data, err := json.Marshal(h.buildProfileResponse(user))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "avatar") {
		t.Fatalf("profile still advertises avatar fields: %s", data)
	}
}
