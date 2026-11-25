package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ledatu/csar-authn/internal/store"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

type discoverySelectionStore struct {
	store.MCPGrantStore
	selection    store.MCPSelection
	err          error
	owner, grant uuid.UUID
	calls        int
}

func (s *discoverySelectionStore) ActiveMCPSelection(_ context.Context, owner, grant uuid.UUID) (store.MCPSelection, error) {
	s.calls++
	s.owner, s.grant = owner, grant
	return s.selection, s.err
}

func TestMCPDiscoverySelectionIsOwnerBoundAndPrivate(t *testing.T) {
	const seller = "25000000-0000-4000-8000-000000000001"
	grant := uuid.New()
	maxSelection := store.MCPSelection{SellerIDs: make([]string, 256)}
	for i := range maxSelection.SellerIDs {
		maxSelection.SellerIDs[i] = seller
	}
	for _, tc := range []struct {
		name               string
		selection          store.MCPSelection
		grantError         error
		principal          string
		trusted, withGrant bool
		status             int
	}{
		{"selected", store.MCPSelection{SellerIDs: []string{seller}}, nil, "svc:aurumskynet-campaigns", true, true, 200},
		{"all", store.MCPSelection{AllCampaigns: true}, nil, "svc:aurumskynet-campaigns", true, true, 200},
		{"legacy consumer", maxSelection, nil, "svc:aurumskynet-campaigns", true, true, 200},
		{"browser", store.MCPSelection{}, nil, "svc:aurumskynet-campaigns", true, false, 200},
		{"revoked or wrong owner", store.MCPSelection{}, store.ErrNotFound, "svc:aurumskynet-campaigns", true, true, 403},
		{"store failure", store.MCPSelection{}, errors.New("unavailable"), "svc:aurumskynet-campaigns", true, true, 503},
		{"other service", store.MCPSelection{}, nil, "svc:other", true, true, 403},
		{"unverified peer", store.MCPSelection{}, nil, "svc:aurumskynet-campaigns", false, true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th := newTestHarness(t)
			th.mock.listSubjectRolesFn = func(context.Context, *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
				return &pb.ListSubjectRolesResponse{Roles: []string{"platform_admin"}}, nil
			}
			db := &discoverySelectionStore{selection: tc.selection, err: tc.grantError}
			ca := &x509.Certificate{Raw: []byte("test root")}
			leaf := &x509.Certificate{Subject: pkix.Name{CommonName: sellerRouterCN}}
			o := sellerOAuth{Handler: th.handler, routerCA: ca, grants: db}
			body := `{"subject":"` + testUserID.String() + `"}`
			if tc.withGrant {
				body = `{"subject":"` + testUserID.String() + `","grant_id":"` + grant.String() + `"}`
			}
			path := "/svc/authn/mcp/eligible"
			if tc.name != "legacy consumer" {
				path += "?selection=v1"
			}
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Gateway-Subject", tc.principal)
			if tc.trusted {
				r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
			}
			w := httptest.NewRecorder()
			o.eligible(w, r)
			if w.Code != tc.status {
				t.Fatalf("status%d: %s", w.Code, w.Body)
			}
			var out struct {
				Selection *store.MCPSelection `json:"selection"`
				Sellers   []string            `json:"seller_ids"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if tc.status == 200 && tc.withGrant && tc.name != "legacy consumer" {
				if out.Selection == nil || out.Selection.AllCampaigns != tc.selection.AllCampaigns || strings.Join(out.Selection.SellerIDs, ",") != strings.Join(tc.selection.SellerIDs, ",") {
					t.Fatalf("wrong consent projection: %s", w.Body)
				}
				if db.owner != testUserID || db.grant != grant || db.calls != 1 {
					t.Fatal("grant lookup changed ownership")
				}
				if len(out.Sellers) != 0 {
					t.Fatal("consent presented as authorized sellers")
				}
			} else if out.Selection != nil {
				t.Fatal("selection leaked on failed or unbound request")
			}
			if tc.name == "legacy consumer" && w.Body.Len() >= 8192 {
				t.Fatal("legacy response no longer fits old client")
			}
			if (!tc.trusted || tc.principal != "svc:aurumskynet-campaigns" || !tc.withGrant) && db.calls != 0 {
				t.Fatal("untrusted request reached grant storage")
			}
		})
	}
}
