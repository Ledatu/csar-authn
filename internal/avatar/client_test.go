package avatar

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateUploadIntentUsesAvatarScope(t *testing.T) {
	var captured struct {
		Scope         string            `json:"scope"`
		Filename      string            `json:"filename"`
		ContentType   string            `json:"content_type"`
		ContentLength int64             `json:"content_length"`
		Metadata      map[string]string `json:"metadata"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Path != "/v1/upload-intents" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"intent":{"id":"ui_test","object":{"key":"avatars/user-1/generated.png"},"upload":{"method":"PUT","url":"https://upload.example.com/avatar","headers":{"x-test":"1"}}}}`))
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		logger:     slog.Default(),
	}

	resp, err := client.CreateUploadIntent(context.Background(), UploadIntentRequest{
		UserID:        "user-1",
		ContentType:   "image/png",
		ContentLength: 512,
		Filename:      "photo.png",
	})
	if err != nil {
		t.Fatalf("CreateUploadIntent returned error: %v", err)
	}

	if captured.Scope != avatarUploadScope {
		t.Fatalf("scope = %q, want %q", captured.Scope, avatarUploadScope)
	}
	if captured.ContentType != "image/png" {
		t.Fatalf("content_type = %q", captured.ContentType)
	}
	if captured.ContentLength != 512 {
		t.Fatalf("content_length = %d", captured.ContentLength)
	}
	if captured.Metadata["owner_user_id"] != "user-1" {
		t.Fatalf("owner_user_id = %q", captured.Metadata["owner_user_id"])
	}
	if captured.Metadata["purpose"] != "avatar" {
		t.Fatalf("purpose = %q", captured.Metadata["purpose"])
	}
	if captured.Filename != "photo.png" {
		t.Fatalf("filename = %q", captured.Filename)
	}
	if resp.UploadToken != "ui_test" {
		t.Fatalf("upload_token = %q", resp.UploadToken)
	}
	if resp.URL != "https://upload.example.com/avatar" {
		t.Fatalf("url = %q", resp.URL)
	}
	if resp.Method != "PUT" {
		t.Fatalf("method = %q", resp.Method)
	}
	if resp.Headers["x-test"] != "1" {
		t.Fatalf("headers[x-test] = %q", resp.Headers["x-test"])
	}
}
