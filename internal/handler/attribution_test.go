package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/store"
)

func TestAttributionCaptureAnonymousUsesCookieState(t *testing.T) {
	h, _, _ := newSessionsHandler(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/attribution/capture", strings.NewReader(`{
		"source_type":"referral_link",
		"source_key":"ref-123",
		"source_metadata":{"landing":"partnerka"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleCaptureAttribution(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	captureCookie := readCookie(t, w.Result().Cookies(), oauth.AttributionCookieName)
	if captureCookie.Value == "" {
		t.Fatal("expected attribution cookie value")
	}

	var captureBody attributionStateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &captureBody); err != nil {
		t.Fatal(err)
	}
	if captureBody.Source != "cookie" {
		t.Fatalf("source = %q, want cookie", captureBody.Source)
	}
	if captureBody.ActiveTouch == nil || captureBody.ActiveTouch.SourceKey != "ref-123" {
		t.Fatalf("unexpected active touch: %+v", captureBody.ActiveTouch)
	}

	currentReq := httptest.NewRequest(http.MethodGet, "/auth/attribution/current", nil)
	currentReq.AddCookie(captureCookie)
	currentW := httptest.NewRecorder()
	h.handleCurrentAttribution(currentW, currentReq)

	if currentW.Code != http.StatusOK {
		t.Fatalf("current expected 200, got %d: %s", currentW.Code, currentW.Body.String())
	}
	var currentBody attributionStateResponse
	if err := json.Unmarshal(currentW.Body.Bytes(), &currentBody); err != nil {
		t.Fatal(err)
	}
	if currentBody.Source != "cookie" {
		t.Fatalf("current source = %q, want cookie", currentBody.Source)
	}
	if currentBody.ActiveTouch == nil || currentBody.ActiveTouch.SourceMetadata["landing"] != "partnerka" {
		t.Fatalf("unexpected current touch: %+v", currentBody.ActiveTouch)
	}
}

func TestAttributionCaptureAuthenticatedPersistsAndShowsInAuthMe(t *testing.T) {
	h, st, sessMgr := newSessionsHandler(t, nil)
	userID := sessionsTestUserID
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "me@test.com",
		DisplayName: "Me",
	})
	sess, err := sessMgr.Create(context.Background(), userID, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/attribution/capture", strings.NewReader(`{
		"source_type":"promo_code",
		"source_key":"PROMO42",
		"source_metadata":{"campaign":"spring"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	w := httptest.NewRecorder()
	h.handleCaptureAttribution(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	touch, err := st.GetActiveUserAttributionTouch(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if touch.SourceType != "promo_code" || touch.SourceKey != "PROMO42" {
		t.Fatalf("unexpected persisted touch: %+v", touch)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	meW := httptest.NewRecorder()
	h.handleMe(meW, meReq)

	if meW.Code != http.StatusOK {
		t.Fatalf("auth/me expected 200, got %d: %s", meW.Code, meW.Body.String())
	}
	var meBody struct {
		Attribution attributionStateResponse `json:"attribution"`
	}
	if err := json.Unmarshal(meW.Body.Bytes(), &meBody); err != nil {
		t.Fatal(err)
	}
	if meBody.Attribution.ActiveTouch == nil {
		t.Fatal("expected active touch in /auth/me")
	}
	if meBody.Attribution.ActiveTouch.SourceType != "promo_code" {
		t.Fatalf("source_type = %q", meBody.Attribution.ActiveTouch.SourceType)
	}
	if !meBody.Attribution.PendingQualification {
		t.Fatal("expected pending_qualification true")
	}
}

func TestAttributionCaptureAuthenticatedReplacesPreviousActiveTouch(t *testing.T) {
	h, st, sessMgr := newSessionsHandler(t, nil)
	userID := sessionsTestUserID
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "me@test.com",
		DisplayName: "Me",
	})
	sess, err := sessMgr.Create(context.Background(), userID, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	firstReq := httptest.NewRequest(http.MethodPost, "/auth/attribution/capture", strings.NewReader(`{
		"source_type":"referral",
		"source_key":"ref-old"
	}`))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	firstW := httptest.NewRecorder()
	h.handleCaptureAttribution(firstW, firstReq)
	if firstW.Code != http.StatusOK {
		t.Fatalf("first capture expected 200, got %d: %s", firstW.Code, firstW.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/auth/attribution/capture", strings.NewReader(`{
		"source_type":"referral",
		"source_key":"ref-new"
	}`))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	secondW := httptest.NewRecorder()
	h.handleCaptureAttribution(secondW, secondReq)
	if secondW.Code != http.StatusOK {
		t.Fatalf("second capture expected 200, got %d: %s", secondW.Code, secondW.Body.String())
	}

	touch, err := st.GetActiveUserAttributionTouch(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if touch.SourceKey != "ref-new" {
		t.Fatalf("active touch source_key = %q, want ref-new", touch.SourceKey)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(&http.Cookie{Name: "session", Value: sess.ID})
	meW := httptest.NewRecorder()
	h.handleMe(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("auth/me expected 200, got %d: %s", meW.Code, meW.Body.String())
	}

	var meBody struct {
		Attribution attributionStateResponse `json:"attribution"`
	}
	if err := json.Unmarshal(meW.Body.Bytes(), &meBody); err != nil {
		t.Fatal(err)
	}
	if meBody.Attribution.ActiveTouch == nil {
		t.Fatal("expected active touch in /auth/me")
	}
	if meBody.Attribution.ActiveTouch.SourceKey != "ref-new" {
		t.Fatalf("auth/me active source_key = %q, want ref-new", meBody.Attribution.ActiveTouch.SourceKey)
	}
}

func TestServiceAttributionResolveAndConsume(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	userID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "service@test.com",
		DisplayName: "Service User",
	})
	touch, err := st.UpsertUserAttributionTouch(context.Background(), &store.AttributionTouch{
		UserID:         userID,
		SourceType:     "referral_link",
		SourceKey:      "ref-service",
		SourceMetadata: map[string]string{"label": "alpha"},
		TouchedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	resolveReq := httptest.NewRequest(http.MethodPost, "/svc/authn/attribution/resolve", strings.NewReader(`{
		"user_id":"`+userID.String()+`"
	}`))
	resolveReq.Header.Set("Content-Type", "application/json")
	resolveW := httptest.NewRecorder()
	h.handleResolveServiceAttribution(resolveW, resolveReq)

	if resolveW.Code != http.StatusOK {
		t.Fatalf("resolve expected 200, got %d: %s", resolveW.Code, resolveW.Body.String())
	}
	var resolveBody attributionResolveResponse
	if err := json.Unmarshal(resolveW.Body.Bytes(), &resolveBody); err != nil {
		t.Fatal(err)
	}
	if resolveBody.Touch == nil || resolveBody.Touch.ID != touch.ID.String() {
		t.Fatalf("unexpected resolve touch: %+v", resolveBody.Touch)
	}

	consumeReq := httptest.NewRequest(http.MethodPost, "/svc/authn/attribution/consume", strings.NewReader(`{
		"user_id":"`+userID.String()+`",
		"touch_id":"`+touch.ID.String()+`"
	}`))
	consumeReq.Header.Set("Content-Type", "application/json")
	consumeW := httptest.NewRecorder()
	h.handleConsumeServiceAttribution(consumeW, consumeReq)

	if consumeW.Code != http.StatusOK {
		t.Fatalf("consume expected 200, got %d: %s", consumeW.Code, consumeW.Body.String())
	}
	var consumeBody attributionResolveResponse
	if err := json.Unmarshal(consumeW.Body.Bytes(), &consumeBody); err != nil {
		t.Fatal(err)
	}
	if consumeBody.Touch == nil || consumeBody.Touch.ConsumedAt == nil {
		t.Fatalf("expected consumed touch, got %+v", consumeBody.Touch)
	}

	resolveAgainReq := httptest.NewRequest(http.MethodPost, "/svc/authn/attribution/resolve", strings.NewReader(`{
		"user_id":"`+userID.String()+`"
	}`))
	resolveAgainReq.Header.Set("Content-Type", "application/json")
	resolveAgainW := httptest.NewRecorder()
	h.handleResolveServiceAttribution(resolveAgainW, resolveAgainReq)

	if resolveAgainW.Code != http.StatusOK {
		t.Fatalf("resolve after consume expected 200, got %d: %s", resolveAgainW.Code, resolveAgainW.Body.String())
	}
	var resolveAgainBody attributionResolveResponse
	if err := json.Unmarshal(resolveAgainW.Body.Bytes(), &resolveAgainBody); err != nil {
		t.Fatal(err)
	}
	if resolveAgainBody.Touch != nil {
		t.Fatalf("expected no active touch after consume, got %+v", resolveAgainBody.Touch)
	}
}

func readCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}
