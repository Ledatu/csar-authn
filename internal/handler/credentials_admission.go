package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/authntokens"
)

// Admission is current authority, never consent metadata or a stored permission.
// Owners may always deny a pending request or revoke their existing credentials.
func (u *credentialIssuer) admitOwner(ctx context.Context, p *authnconfig.CredentialProfile, owner string) error {
	if p == nil {
		return store.ErrCredentialInvalid
	}
	a := p.Admission
	if a == nil {
		return nil
	}
	results, err := u.decideProfile(ctx, p.Audience, a.DecisionProfile, owner, []authntokens.ResourceRef{a.Resource})
	if err != nil {
		return err
	}
	result := results[0]
	if !result.Allowed || result.Scope == nil || *result.Scope != a.RequiredScope {
		return store.ErrCredentialInvalid
	}
	return nil
}
func (u *credentialIssuer) requireAdmission(w http.ResponseWriter, r *http.Request, p *authnconfig.CredentialProfile, owner string) bool {
	if err := u.admitOwner(r.Context(), p, owner); err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, store.ErrCredentialInvalid) {
			status = http.StatusForbidden
		}
		credentialError(w, status)
		return false
	}
	return true
}
