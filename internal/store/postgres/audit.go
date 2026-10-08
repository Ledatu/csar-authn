package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
)

func (s *Store) EnableAuditOutbox(ctx context.Context) (*audit.PGOutbox, error) {
	o, err := audit.NewPGOutbox(s.pool, "csar-authn")
	if err != nil {
		return nil, err
	}
	if err := o.Migrate(ctx); err != nil {
		return nil, err
	}
	s.outbox = o
	return o, nil
}

// TransactionalAudit reports only action classes covered by this store.
func (s *Store) TransactionalAudit(action string) bool {
	if s.outbox == nil {
		return false
	}
	switch action {
	case "service_account.create", "service_account.reactivate", "service_account.policy_update", "service_account.rotate", "service_account.revoke", "api_key.create", "api_key.revoke":
		return true
	default:
		return false
	}
}

func (s *Store) enqueueSA(ctx context.Context, tx pgx.Tx, action string, sa *store.ServiceAccount) error {
	if s.outbox == nil {
		return nil
	}
	fingerprint := sha256.Sum256([]byte(sa.PublicKeyPEM))
	state, err := json.Marshal(map[string]any{"name": sa.Name, "status": sa.Status, "allowed_audiences": sa.AllowedAudiences, "allow_all_audiences": sa.AllowAllAudiences, "token_ttl": sa.TokenTTL.String(), "revision": sa.Revision, "generation": sa.Generation, "key_fingerprint": hex.EncodeToString(fingerprint[:])})
	if err != nil {
		return err
	}
	id, _ := gatewayctx.FromContext(ctx)
	actor := id.Subject
	if actor == "" {
		actor = "unattributed:csar-authn"
	}
	return s.outbox.EnqueueTx(ctx, tx, &audit.Event{Actor: actor, Action: action, TargetType: "service_account", TargetID: sa.Name, ScopeType: "platform", AfterState: state, RequestID: id.RequestID})
}

func (s *Store) enqueueAPIKey(ctx context.Context, tx pgx.Tx, action string, key *store.APICredential, owner string) error {
	if s.outbox == nil {
		return nil
	}
	id, _ := gatewayctx.FromContext(ctx)
	return s.outbox.EnqueueTx(ctx, tx, &audit.Event{Actor: owner, Action: action, TargetType: "api_key", TargetID: key.ID.String(), ScopeType: "tenant", ScopeID: "wildberries:" + key.SellerID, RequestID: id.RequestID})
}
