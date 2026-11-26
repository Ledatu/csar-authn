package store

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/ledatu/csar-core/authntokens"
)

func TestCredentialConsentStrictVersionAndExactRevision(t *testing.T) {
	valid := authntokens.GrantConstraints{Version: 1, ProfileID: "workspace-reader", ProfileRevision: math.MaxUint64, Audience: "https://example.test/api", Scopes: []string{"facts:read"}, Namespaces: []string{"documents"}, Selection: authntokens.ResourceSelection{Mode: authntokens.Selected, Resources: []authntokens.ResourceRef{{Namespace: "documents", ID: "opaque-17"}}}}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var got authntokens.GrantConstraints
	if DecodeCredentialJSON(raw, &got) != nil || got.Validate() != nil || got.ProfileRevision != math.MaxUint64 {
		t.Fatal("revision or consent changed")
	}
	for _, raw := range []string{`{"version":1,"Version":2}`, `{"version":1,"future_required":true}`, `{"version":1} {}`, `null`} {
		if DecodeCredentialJSON([]byte(raw), &got) == nil {
			t.Fatal("ambiguous/unsupported document accepted")
		}
	}
	valid.Version = 2
	if valid.Validate() == nil {
		t.Fatal("future consent accepted")
	}
	valid.Version = 1
	valid.Selection.Resources = append(valid.Selection.Resources, valid.Selection.Resources[0])
	if valid.Validate() == nil {
		t.Fatal("duplicate consent accepted")
	}
}
