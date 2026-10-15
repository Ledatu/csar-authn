package emailotp

import (
	"context"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/email"
	"github.com/ledatu/csar-core/secret"
)

type fakeEmailClient struct {
	msg email.Message
	err error
}

func (c *fakeEmailClient) Send(_ context.Context, msg *email.Message) (email.Receipt, error) {
	c.msg = *msg
	return email.Receipt{}, c.err
}

func TestEmailSenderSendOTPDelegatesMessage(t *testing.T) {
	cfg := authnconfig.EmailOTPConfig{
		SenderAddress: "login@example.com",
		SenderName:    "AURUMSKYNET ID",
		Subject:       "Your code",
	}
	client := &fakeEmailClient{}
	sender := newEmailSender(cfg, client)
	if err := sender.SendOTP(context.Background(), "user@example.com", "123456"); err != nil {
		t.Fatalf("SendOTP() error = %v", err)
	}
	if client.msg.From != `"AURUMSKYNET ID" <login@example.com>` {
		t.Fatalf("From = %q", client.msg.From)
	}
	if client.msg.To != "user@example.com" {
		t.Fatalf("unexpected destination: %#v", client.msg.To)
	}
	if client.msg.Subject != "Your code" {
		t.Fatalf("subject = %q", client.msg.Subject)
	}
	if client.msg.TextBody == "" || client.msg.HTMLBody == "" {
		t.Fatal("expected text and HTML bodies")
	}
	if !strings.Contains(client.msg.TextBody, "123456") || !strings.Contains(client.msg.HTMLBody, "123456") {
		t.Fatal("expected OTP code in rendered bodies")
	}
}

func TestEmailSenderPropagatesTransportFailure(t *testing.T) {
	client := &fakeEmailClient{err: &email.SendError{Stage: "acceptance", Outcome: email.Unknown}}
	sender := newEmailSender(authnconfig.EmailOTPConfig{SenderAddress: "login@example.com", Subject: "Your code"}, client)
	if err := sender.SendOTP(context.Background(), "user@example.com", "123456"); err != client.err {
		t.Fatalf("transport outcome lost: %v", err)
	}
}

func TestSelectelSenderDoesNotRequireYandexCredentials(t *testing.T) {
	cfg := authnconfig.EmailOTPConfig{SenderAddress: "login@example.com", Subject: "Your code", Delivery: &email.Config{Provider: email.ProviderSelectel, Selectel: &email.SMTPConfig{Username: "test-user", Password: secret.NewSecret("test-password")}}}
	if _, err := NewSender(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
