package handler

import (
	"errors"
	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
	"net/http"
)

// eligible filters a bounded page supplied by Campaigns. The private gateway route pins
// the Campaigns service account; the subject and optional grant originate in its trusted request context.
func (o *sellerOAuth) eligible(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !o.verifiedRouter(r.TLS) || r.Header.Get(gatewayctx.HeaderSubject) != "svc:aurumskynet-campaigns" {
		oauthError(w, 403, "access_denied")
		return
	}
	var in struct {
		Subject uuid.UUID `json:"subject"`
		Grant   string    `json:"grant_id"`
		Sellers []string  `json:"seller_ids"`
		Issue   bool      `json:"issue_report_proof"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if httpx.ReadJSON(r, &in) != nil || in.Subject == uuid.Nil || len(in.Sellers) > 100 {
		oauthError(w, 400, "invalid_request")
		return
	}
	if in.Issue && (in.Grant == "" || len(in.Sellers) != 1) {
		oauthError(w, 400, "invalid_request")
		return
	}
	selection := store.MCPSelection{AllCampaigns: true}
	if in.Grant != "" {
		grant, err := uuid.Parse(in.Grant)
		if err != nil {
			oauthError(w, 400, "invalid_request")
			return
		}
		selection, err = o.grants.ActiveMCPSelection(r.Context(), in.Subject, grant)
		if errors.Is(err, store.ErrNotFound) {
			oauthError(w, 403, "access_denied")
			return
		}
		if err != nil {
			oauthError(w, 503, "temporarily_unavailable")
			return
		}
	}
	ids := make([]string, 0, len(in.Sellers))
	for _, seller := range in.Sellers {
		if !validWBSellerID(seller) {
			oauthError(w, 400, "invalid_request")
			return
		}
		if !selection.Allows(seller) {
			continue
		}
		ok, err := o.checkSellerAction(r, in.Subject, seller, "analytics.read")
		if err != nil {
			oauthError(w, 503, "temporarily_unavailable")
			return
		}
		if ok {
			ids = append(ids, seller)
		}
	}
	response := map[string]any{"seller_ids": ids}
	if in.Issue && len(ids) == 1 {
		proof := "aurum_dlg_" + randomToken()
		err := o.grants.IssueMCPReport(r.Context(), in.Subject, uuid.MustParse(in.Grant), ids[0], hashValue(proof))
		if errors.Is(err, store.ErrNotFound) {
			oauthError(w, 403, "access_denied")
			return
		}
		if err != nil {
			oauthError(w, 503, "temporarily_unavailable")
			return
		}
		response["report_proof"] = proof
	}
	httpx.WriteJSON(w, 200, response)
}
