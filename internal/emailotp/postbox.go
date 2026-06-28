package emailotp

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/mail"

	"github.com/ledatu/csar-core/postbox"

	"github.com/ledatu/csar-authn/internal/config"
)

// Sender sends one-time codes to normalized email addresses.
type Sender interface {
	SendOTP(ctx context.Context, to string, code string) error
}

type emailClient interface {
	SendEmail(ctx context.Context, msg *postbox.Message) error
}

// PostboxSender sends email through the Yandex Cloud Postbox HTTP API.
type PostboxSender struct {
	from    string
	subject string
	client  emailClient
}

// NewPostboxSender creates a Postbox sender using the shared Yandex Cloud IAM resolver.
func NewPostboxSender(cfg config.EmailOTPConfig, client *http.Client) (*PostboxSender, error) {
	postboxClient, err := postbox.NewClient(&cfg.Postbox, client)
	if err != nil {
		return nil, fmt.Errorf("initializing postbox client: %w", err)
	}
	return newPostboxSender(cfg, postboxClient), nil
}

func newPostboxSender(cfg config.EmailOTPConfig, client emailClient) *PostboxSender {
	from := cfg.SenderAddress
	if cfg.SenderName != "" {
		from = (&mail.Address{Name: cfg.SenderName, Address: cfg.SenderAddress}).String()
	}
	return &PostboxSender{
		from:    from,
		subject: cfg.Subject,
		client:  client,
	}
}

// SendOTP sends a one-time code. It never returns or logs the code.
func (s *PostboxSender) SendOTP(ctx context.Context, to string, code string) error {
	return s.client.SendEmail(ctx, &postbox.Message{
		FromEmailAddress: s.from,
		ToAddresses:      []string{to},
		Subject:          s.subject,
		TextBody:         textBody(code),
		HTMLBody:         htmlBody(code),
	})
}

func textBody(code string) string {
	return fmt.Sprintf("Your AURUMSKYNET sign-in code is %s. It expires in a few minutes. If you did not request this code, you can ignore this email.", code)
}

func htmlBody(code string) string {
	escapedCode := html.EscapeString(code)
	return fmt.Sprintf(`<p>Your AURUMSKYNET sign-in code is:</p><p><strong>%s</strong></p><p>It expires in a few minutes. If you did not request this code, you can ignore this email.</p>`, escapedCode)
}
