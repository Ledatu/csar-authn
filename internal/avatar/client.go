package avatar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ledatu/csar-core/stsclient"
)

const (
	maxErrorBodyBytes = 4096
	avatarUploadScope = "authn-avatars"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

type UploadIntentRequest struct {
	UserID        string `json:"user_id"`
	ContentType   string `json:"content_type"`
	ContentLength int64  `json:"content_length"`
	Filename      string `json:"filename,omitempty"`
}

type UploadIntentResponse struct {
	UploadToken string            `json:"upload_token,omitempty"`
	ObjectKey   string            `json:"object_key,omitempty"`
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type FinalizeAvatarRequest struct {
	UserID      string `json:"user_id"`
	UploadToken string `json:"upload_token"`
}

type FinalizeAvatarResponse struct {
	StorageKey  string `json:"storage_key,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size,omitempty"`
	URL         string `json:"url,omitempty"`
	SignedURL   string `json:"signed_url,omitempty"`
}

type SignedReadURLResponse struct {
	URL       string `json:"url,omitempty"`
	SignedURL string `json:"signed_url,omitempty"`
}

type uploadIntentEnvelope struct {
	Intent struct {
		ID     string `json:"id"`
		Object struct {
			Key         string `json:"key"`
			ContentType string `json:"content_type,omitempty"`
			Size        int64  `json:"size,omitempty"`
		} `json:"object"`
		Upload struct {
			Method  string            `json:"method,omitempty"`
			URL     string            `json:"url,omitempty"`
			Headers map[string]string `json:"headers,omitempty"`
		} `json:"upload"`
	} `json:"intent"`
	StorageKey string `json:"storage_key,omitempty"`
}

type readLinkEnvelope struct {
	Link struct {
		URL string `json:"url,omitempty"`
	} `json:"link"`
}

func New(serviceAuth *stsclient.ServiceAuthConfig, logger *slog.Logger) (*Client, error) {
	if serviceAuth == nil {
		return nil, nil
	}
	if err := serviceAuth.Validate(); err != nil {
		return nil, fmt.Errorf("avatar service auth: %w", err)
	}
	if !serviceAuth.IsConfigured() {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	rc, err := stsclient.NewRouterClient(serviceAuth, logger.With("component", "avatar-router-client"))
	if err != nil {
		return nil, fmt.Errorf("avatar router client: %w", err)
	}

	return &Client{
		baseURL:    strings.TrimRight(rc.BaseURL, "/"),
		httpClient: rc.Client,
		logger:     logger,
	}, nil
}

func (c *Client) CreateUploadIntent(ctx context.Context, req UploadIntentRequest) (*UploadIntentResponse, error) {
	var resp uploadIntentEnvelope
	body := map[string]any{
		"scope":          avatarUploadScope,
		"filename":       strings.TrimSpace(req.Filename),
		"content_type":   req.ContentType,
		"content_length": req.ContentLength,
		"metadata": map[string]string{
			"owner_user_id": req.UserID,
			"purpose":       "avatar",
		},
	}
	if err := c.doJSON(ctx, http.MethodPost, c.path("/v1/upload-intents"), body, http.StatusCreated, &resp); err != nil {
		return nil, err
	}
	return &UploadIntentResponse{
		UploadToken: resp.Intent.ID,
		ObjectKey:   resp.Intent.Object.Key,
		Method:      resp.Intent.Upload.Method,
		URL:         resp.Intent.Upload.URL,
		Headers:     resp.Intent.Upload.Headers,
	}, nil
}

func (c *Client) FinalizeAvatar(ctx context.Context, req FinalizeAvatarRequest) (*FinalizeAvatarResponse, error) {
	var resp uploadIntentEnvelope
	if err := c.doJSON(ctx, http.MethodPost, c.path("/v1/upload-intents/"+url.PathEscape(req.UploadToken)+"/finalize"), nil, http.StatusOK, &resp); err != nil {
		return nil, err
	}
	return &FinalizeAvatarResponse{
		StorageKey:  resp.StorageKey,
		ContentType: resp.Intent.Object.ContentType,
		Size:        resp.Intent.Object.Size,
	}, nil
}

func (c *Client) DeleteObject(ctx context.Context, storageKey string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.path("/v1/objects/"+escapePathSegments(storageKey)), nil)
	if err != nil {
		return fmt.Errorf("avatar delete request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("avatar delete request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("avatar delete status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) SignedReadURL(ctx context.Context, storageKey string) (string, error) {
	var resp readLinkEnvelope
	if err := c.doJSON(ctx, http.MethodPost, c.path("/v1/read-links"), map[string]string{"storage_key": storageKey}, http.StatusCreated, &resp); err != nil {
		return "", err
	}
	if resp.Link.URL != "" {
		return resp.Link.URL, nil
	}
	return "", fmt.Errorf("avatar read url response missing url")
}

func (c *Client) doJSON(ctx context.Context, method, requestURL string, body any, wantStatus int, out any) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("avatar marshal request: %w", err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, payload)
	if err != nil {
		return fmt.Errorf("avatar request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("avatar request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("avatar status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("avatar decode response: %w", err)
	}
	return nil
}

func (c *Client) path(suffix string) string {
	return c.baseURL + suffix
}

func escapePathSegments(value string) string {
	parts := strings.Split(value, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
