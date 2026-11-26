package postgres

import (
	"context"
	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
)

// CredentialCapacity uses the mutation path's exact mixed-family counts.
func (s *Store) CredentialCapacity(ctx context.Context, owner uuid.UUID) (store.CredentialCapacity, error) {
	var out store.CredentialCapacity
	if owner == uuid.Nil {
		return out, store.ErrCredentialInvalid
	}
	if err := s.pool.QueryRow(ctx, apiCredentialCountSQL, owner).Scan(&out.APIKeys); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, connectionCredentialCountSQL, owner).Scan(&out.Connections); err != nil {
		return out, err
	}
	return out, nil
}
