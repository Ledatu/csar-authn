package main

import "testing"

func TestOptionalMCPFeatureFlags(t *testing.T) {
	for _, value := range []string{"", "true", "false", "invalid"} {
		t.Setenv("MCP_OAUTH_DYNAMIC_CLIENTS", value)
		got, err := optionalBoolEnv("MCP_OAUTH_DYNAMIC_CLIENTS", false)
		if (err != nil) != (value == "invalid") || got != (value == "true") {
			t.Fatalf("flag %q: %v %v", value, got, err)
		}
	}
}
