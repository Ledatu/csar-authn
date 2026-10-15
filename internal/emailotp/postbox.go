package emailotp

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/mail"

	"github.com/ledatu/csar-core/email"

	"github.com/ledatu/csar-authn/internal/config"
)

// Sender sends one-time codes to normalized email addresses.
type Sender interface {
	SendOTP(ctx context.Context, to string, code string) error
}

type emailClient interface {
	Send(context.Context, *email.Message) (email.Receipt, error)
}

// EmailSender renders OTP messages and delegates to the selected transport.
type EmailSender struct {
	from    string
	subject string
	client  emailClient
}

// NewSender constructs provider-neutral OTP delivery. No message is sent here.
func NewSender(cfg config.EmailOTPConfig, client *http.Client) (*EmailSender, error) {
	transport, err := email.NewSender(cfg.EmailDelivery(), client)
	if err != nil {
		return nil, fmt.Errorf("initializing email transport: %w", err)
	}
	return newEmailSender(cfg, transport), nil
}

// PostboxSender preserves the legacy constructor/type for existing callers.
type PostboxSender = EmailSender

// NewPostboxSender constructs OTP delivery using the legacy Postbox settings.
func NewPostboxSender(cfg config.EmailOTPConfig, client *http.Client) (*PostboxSender, error) {
	cfg.Delivery = nil
	return NewSender(cfg, client)
}

func newEmailSender(cfg config.EmailOTPConfig, client emailClient) *EmailSender {
	from := cfg.SenderAddress
	if cfg.SenderName != "" {
		from = (&mail.Address{Name: cfg.SenderName, Address: cfg.SenderAddress}).String()
	}
	return &EmailSender{
		from:    from,
		subject: cfg.Subject,
		client:  client,
	}
}

// SendOTP sends a one-time code. It never returns or logs the code.
func (s *EmailSender) SendOTP(ctx context.Context, to string, code string) error {
	_, err := s.client.Send(ctx, &email.Message{
		From: s.from, To: to, Subject: s.subject, TextBody: textBody(code), HTMLBody: htmlBody(code),
	})
	return err
}

func textBody(code string) string {
	return fmt.Sprintf("Your AURUMSKYNET sign-in code is %s. It expires in a few minutes. If you did not request this code, you can ignore this email.", code)
}

func htmlBody(code string) string {
	escapedCode := html.EscapeString(code)
	return fmt.Sprintf(`<p>Your AURUMSKYNET sign-in code is:</p><p><strong>%s</strong></p><p>It expires in a few minutes. If you did not request this code, you can ignore this email.</p>`, escapedCode)
}
