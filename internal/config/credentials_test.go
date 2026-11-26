package config

import (
	"strings"
	"testing"
)

const genericReceiverConfig = `base_url: https://id.example.test
database: {dsn: postgres://fixture}
oauth: {enabled: false}
cookie: {secure: true}
audit_outbox_enabled: true
audit:
  router_base_url: https://router.example.test
  sts_endpoint: https://id.example.test/sts/token
  audience: https://router.example.test
  service_name: issuer
  assertion_audience: https://id.example.test/sts/token
  jwt: {private_key_file: /service/key.pem, public_key_file: /service/public.pem}
tls: {enabled: true, cert_file: /server/cert.pem, key_file: /server/key.pem, client_ca_file: /general/ca.pem}
credentials:
  version: 1
  enabled: true
  issuer_url: https://id.example.test
  consent_url: https://console.example.test/consent
  mutation_origins: [https://console.example.test]
  consent_cookie_name: __Host-credential-consent
  decisions:
    router_base_url: https://router.example.test
    sts_endpoint: https://id.example.test/sts/token
    audience: https://router.example.test
    service_name: issuer
    assertion_audience: https://id.example.test/sts/token
    router_timeout: 5s
    jwt: {private_key_file: /service/key.pem, public_key_file: /service/public.pem}
  trust_policies:
    - {id: ingress, ca_file: /dedicated/ca.pem, peer_cn: credentials-router}
  profiles:
    - id: facts
      revision: 2
      accepted_grant_revisions: [1, 2]
      audience: https://facts.example.test
      scopes: [{scope: 'facts:read', decision_profile: facts-reader}]
      namespaces: [workspace]
      selection_modes: [selected, current_and_future]
      access_ttl: 1h
      grant_ttl: 24h
      proof_ttl: 1m
      trust_policy: ingress
`

func TestGenericReceiverRequiresSecureSessionTLSAndAudit(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(genericReceiverConfig))
	if err != nil || cfg.Credentials == nil || !cfg.Credentials.Enabled {
		t.Fatal("compatible runtime opt-in rejected", err)
	}
	for _, change := range []struct{ old, new string }{{"cookie: {secure: true}", "cookie: {secure: false}"}, {"audit_outbox_enabled: true", "audit_outbox_enabled: false"}, {"tls: {enabled: true, cert_file: /server/cert.pem, key_file: /server/key.pem, client_ca_file: /general/ca.pem}", ""}} {
		if _, err := LoadFromBytes([]byte(strings.Replace(genericReceiverConfig, change.old, change.new, 1))); err == nil {
			t.Fatal("incomplete runtime enabled", change.old)
		}
	}
	next := *cfg
	next.Cookie = cfg.Cookie
	next.Cookie.Name = "changed"
	if ValidateReload(cfg, &next) == nil {
		t.Fatal("generic owner cookie changed on reload")
	}
	next = *cfg
	next.TLS = cfg.TLS
	next.TLS.ClientCAFile = "/other/ca.pem"
	if ValidateReload(cfg, &next) == nil {
		t.Fatal("issuer transport changed on reload")
	}
}

func TestManualIssuancePolicyIsCapturedAtStartup(t *testing.T) {
	declaration := strings.Replace(genericReceiverConfig, "      revision: 2", "      revision: 2\n      manual_issuance: {family: connection, max_ttl: 24h}", 1)
	cfg, err := LoadFromBytes([]byte(declaration))
	if err != nil || cfg.Credentials.Profiles[0].ManualIssuance == nil || cfg.Credentials.Profiles[0].ManualIssuance.Family != "connection" {
		t.Fatal("manual receiver policy rejected", err)
	}
	next, err := LoadFromBytes([]byte(strings.Replace(declaration, "max_ttl: 24h", "max_ttl: 12h", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if ValidateReload(cfg, next) == nil {
		t.Fatal("manual lifetime changed during partial reload")
	}
}
