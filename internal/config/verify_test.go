package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
)

// The verification section is optional, and a profile that does not ask for it
// behaves exactly as before.
func TestVerificationIsOptional(t *testing.T) {
	p, err := config.Parse([]byte(minimalProfile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Verify.Enabled {
		t.Error("verification is enabled although the profile did not ask for it")
	}
}

// A profile that asks for verification must say how to reach the reader. A
// half-configured stage would fail silently, and silence is what a passing
// check looks like from the outside.
func TestEnabledVerificationRequiresAnEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		want    string
	}{
		{
			name:    "no base URL",
			profile: "verify:\n  enabled: true\n  model: gpt-4o-mini\n  api_key_env: KEY\n",
			want:    "verify.base_url is required",
		},
		{
			name:    "no model",
			profile: "verify:\n  enabled: true\n  base_url: https://example.test/v1\n  api_key_env: KEY\n",
			want:    "verify.model is required",
		},
		{
			name:    "no key variable",
			profile: "verify:\n  enabled: true\n  base_url: https://example.test/v1\n  model: gpt-4o-mini\n",
			want:    "verify.api_key_env is required",
		},
		{
			name: "unknown fallback",
			profile: "verify:\n  enabled: true\n  base_url: https://example.test/v1\n  model: gpt-4o-mini\n" +
				"  api_key_env: KEY\n  on_unavailable: guess\n",
			want: "verify.on_unavailable must be suppress or deliver",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(withVerifySection(tc.profile)))
			if err == nil {
				t.Fatal("the profile was accepted although verification cannot work")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// A complete verification section is accepted, and its conservative defaults
// are applied.
func TestVerificationDefaultsAreApplied(t *testing.T) {
	p, err := config.Parse([]byte(withVerifySection(
		"verify:\n  enabled: true\n  base_url: https://example.test/v1\n" +
			"  model: gpt-4o-mini\n  api_key_env: HUNTER_LLM_API_KEY\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Verify.Enabled {
		t.Fatal("verification was not enabled")
	}
	if p.Verify.OnUnavailable != "suppress" {
		t.Errorf("on_unavailable = %q, want suppress", p.Verify.OnUnavailable)
	}
	if p.Verify.Timeout.Value() <= 0 {
		t.Error("no timeout was defaulted")
	}
	if p.Verify.Timeout.Value() < 30*time.Second {
		t.Errorf("timeout = %v, want a reader to be given room", p.Verify.Timeout.Value())
	}
}

// withVerifySection adds a verification section to the minimal profile.
//
// The section is indented under the profile key, because the minimal profile
// uses the nested document shape.
func withVerifySection(section string) string {
	indented := strings.ReplaceAll(strings.TrimRight(section, "\n"), "\n", "\n  ")
	return strings.Replace(minimalProfile, "  name: minimal\n", "  name: minimal\n  "+indented+"\n", 1)
}
