package session

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func TestValidatedImpersonationDeadlineRespectsAbsoluteMaxAge(t *testing.T) {
	st := mock.New()
	m := NewSessionManager(st, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Minute, time.Hour, time.Hour)
	sess, err := m.CreateImpersonated(t.Context(), uuid.New(), uuid.New(), "test", "ua", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := m.Validate(t.Context(), sess.ID)
	if err != nil || !validated.ExpiresAt.Equal(sess.CreatedAt.Add(time.Minute)) {
		t.Fatal("validation exposed a deadline beyond absolute max age", err)
	}
}
