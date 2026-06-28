package emailotp

import (
	"context"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/postbox"
)

type fakeEmailClient struct {
	msg postbox.Message
	err error
}

func (c *fakeEmailClient) SendEmail(_ context.Context, msg *postbox.Message) error {
	c.msg = *msg
	return c.err
}

func TestPostboxSenderSendOTPDelegatesMessage(t *testing.T) {
	cfg := authnconfig.EmailOTPConfig{
		SenderAddress: "login@example.com",
		SenderName:    "AURUMSKYNET ID",
		Subject:       "Your code",
	}
	client := &fakeEmailClient{}
	sender := newPostboxSender(cfg, client)
	if err := sender.SendOTP(context.Background(), "user@example.com", "123456"); err != nil {
		t.Fatalf("SendOTP() error = %v", err)
	}
	if client.msg.FromEmailAddress != `"AURUMSKYNET ID" <login@example.com>` {
		t.Fatalf("FromEmailAddress = %q", client.msg.FromEmailAddress)
	}
	if len(client.msg.ToAddresses) != 1 || client.msg.ToAddresses[0] != "user@example.com" {
		t.Fatalf("unexpected destination: %#v", client.msg.ToAddresses)
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
