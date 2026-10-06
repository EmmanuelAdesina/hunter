package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// minimalProfile is the smallest profile that validates.
const minimalProfile = `
profile:
  name: minimal
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
  notifications:
    alert_on_new_programs: true
    new_program_window: 24h
    change_windows:
      default: 72h
`

// TestTheShippedProfileIsValid verifies the profile that ships with the
// repository parses and reflects the stated research constraints.
func TestTheShippedProfileIsValid(t *testing.T) {
	p, err := config.Load(filepath.Join("..", "..", "configs", "profiles", "personal.yaml"))
	if err != nil {
		t.Fatalf("the shipped profile does not validate: %v", err)
	}

	if p.Name != "personal" {
		t.Errorf("name = %q, want personal", p.Name)
	}
	if p.Access.MaxReputationPoints != 80 {
		t.Errorf("max_reputation_points = %d, want 80", p.Access.MaxReputationPoints)
	}
	if p.Access.MaxSubmissionFeeUSD != 5 {
		t.Errorf("max_submission_fee_usd = %v, want 5", p.Access.MaxSubmissionFeeUSD)
	}
	if p.Access.KYCRequired != domain.TriNo {
		t.Errorf("kyc_required = %s, want no", p.Access.KYCRequired)
	}
	if p.Access.AcceptUnknownAccessGates {
		t.Error("the shipped profile accepts unknown access gates; that would let a " +
			"parser regression approve every program")
	}
	if p.Access.AcceptUnknownParseState {
		t.Error("the shipped profile accepts unparseable records")
	}

	// The crypto posture is the mandate's central requirement, so it is checked
	// explicitly rather than merely parsed.
	allowed := p.AllowedCryptoTraits()
	for _, want := range []domain.CryptoTrait{
		domain.CryptoTraitPlatform, domain.CryptoTraitExchange, domain.CryptoTraitAPI,
	} {
		if !allowed.Has(want) {
			t.Errorf("crypto allow list is missing %s", want)
		}
	}
	excluded := p.ExcludedCryptoTraits()
	for _, want := range []domain.CryptoTrait{
		domain.CryptoTraitSmartContract, domain.CryptoTraitSolidityOnly,
		domain.CryptoTraitConsensus, domain.CryptoTraitCoreProtocol,
	} {
		if !excluded.Has(want) {
			t.Errorf("crypto exclude list is missing %s", want)
		}
	}
	if excluded.Has(domain.CryptoTraitPlatform) {
		t.Error("crypto_platform is excluded, which would reject every crypto business")
	}
	if p.CryptoDominanceRatio() <= 0 || p.CryptoDominanceRatio() > 1 {
		t.Errorf("crypto dominance ratio = %v, want a fraction", p.CryptoDominanceRatio())
	}

	included := domain.NewTags(p.TargetDomains.Included...)
	for _, want := range []string{"web_application", "api", "backend", "codebase"} {
		if !included.Has(want) {
			t.Errorf("target domains are missing %s", want)
		}
	}

	states := p.AllowedStates()
	if len(states) != 2 || states[0] != domain.StateLive || states[1] != domain.StateNew {
		t.Errorf("allowed states = %v, want live and new", states)
	}
	if len(p.EnabledSources()) != 1 || p.EnabledSources()[0] != "hackenproof" {
		t.Errorf("sources = %v, want hackenproof", p.EnabledSources())
	}
	if !p.Scan.FetchDetails {
		t.Error("the shipped profile disables detail fetches, which would make " +
			"access gates unknown")
	}
}

// TestChangeWindowsRequireAnExplicitDefault verifies every test profile must
// declare a recency fallback rather than silently leaving a trigger unbounded.
func TestChangeWindowsRequireAnExplicitDefault(t *testing.T) {
	profile := strings.Replace(minimalProfile, "      default: 72h\n", "", 1)
	_, err := config.Parse([]byte(profile))
	if err == nil {
		t.Fatal("a profile with no change_windows.default was accepted")
	}
	if !strings.Contains(err.Error(), "notifications.change_windows.default") {
		t.Errorf("error = %v, want it to identify the missing change-window default", err)
	}
}

// TestChangeWindowMaxAgeDefaultsToWidestTriggerWindow verifies derived expiry
// tracks the broadest configured trigger window instead of expiring eligible
// windows prematurely.
func TestChangeWindowMaxAgeDefaultsToWidestTriggerWindow(t *testing.T) {
	profile := strings.Replace(minimalProfile, "default: 72h", "default: 72h\n      access_improved: 168h", 1)
	p, err := config.Parse([]byte(profile))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	if got := p.ChangeWindowMaxAge(); got != 168*time.Hour {
		t.Errorf("derived window max age = %s, want the widest trigger window of 168h", got)
	}
}

// TestDefaultsAreApplied verifies omitted keys take sensible values rather than
// zero, since a zero reputation ceiling would reject every program.
func TestDefaultsAreApplied(t *testing.T) {
	p, err := config.Parse([]byte(minimalProfile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if p.Scan.PerPage != 10 {
		t.Errorf("per_page = %d, want the default 10", p.Scan.PerPage)
	}
	if p.Scan.MaxConcurrent != 2 {
		t.Errorf("max_concurrent = %d, want the default 2", p.Scan.MaxConcurrent)
	}
	if p.ScanDuration("request_timeout") != 20*time.Second {
		t.Errorf("request_timeout = %v, want a default", p.ScanDuration("request_timeout"))
	}
	if p.MinSeverity() != domain.SeverityMedium {
		t.Errorf("min_severity = %s, want medium", p.MinSeverity())
	}
	if p.DetailsRefreshInterval() != 24*time.Hour {
		t.Errorf("details_refresh_interval = %v, want 24h", p.DetailsRefreshInterval())
	}
	if p.FreshProgramWindow() != 7*24*time.Hour {
		t.Errorf("fresh_program_window = %v, want 168h", p.FreshProgramWindow())
	}
	// An unspecified KYC stance must narrow results, never widen them.
	if p.Access.KYCRequired != domain.TriNo {
		t.Errorf("default kyc stance = %s, want no", p.Access.KYCRequired)
	}
	if !p.FetchDetailsOnListingChange() {
		t.Error("the listing-change trigger defaults to off; the cheap tier would " +
			"never notice a real change")
	}
}

// TestOverridesTakeEffect verifies policy values come from configuration, which
// is the promise that changing the profile changes behaviour without code.
func TestOverridesTakeEffect(t *testing.T) {
	p, err := config.Parse([]byte(strings.Replace(minimalProfile,
		"max_reputation_points: 80", "max_reputation_points: 250", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Access.MaxReputationPoints != 250 {
		t.Errorf("max_reputation_points = %d, want the configured 250", p.Access.MaxReputationPoints)
	}

	p, err = config.Parse([]byte(strings.Replace(minimalProfile,
		"kyc_required: no", "kyc_required: yes", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Access.KYCRequired != domain.TriYes {
		t.Errorf("kyc_required = %s, want the configured yes", p.Access.KYCRequired)
	}

	p, err = config.Parse([]byte(strings.Replace(minimalProfile,
		"name: minimal", "name: minimal\n  crypto:\n    enabled: true\n    mode: all", 1)))
	if err == nil {
		t.Errorf("crypto mode 'all' was accepted: %v", p)
	}
}

// TestOmittedNumericDefaultsAndExplicitZero verifies omitted integer policy
// values receive their documented defaults while an intentional zero is kept.
func TestOmittedNumericDefaultsAndExplicitZero(t *testing.T) {
	omitted := strings.Replace(minimalProfile, "    max_reputation_points: 80\n", "", 1)
	p, err := config.Parse([]byte(omitted))
	if err != nil {
		t.Fatalf("parse omitted reputation ceiling: %v", err)
	}
	if p.Access.MaxReputationPoints != 80 {
		t.Errorf("omitted max_reputation_points = %d, want default 80", p.Access.MaxReputationPoints)
	}

	explicitZero := strings.Replace(minimalProfile, "max_reputation_points: 80", "max_reputation_points: 0", 1)
	p, err = config.Parse([]byte(explicitZero))
	if err != nil {
		t.Fatalf("parse explicit zero reputation ceiling: %v", err)
	}
	if p.Access.MaxReputationPoints != 0 {
		t.Errorf("explicit max_reputation_points = %d, want 0", p.Access.MaxReputationPoints)
	}
}

// TestExplicitFalseOverridesBooleanDefault verifies YAML key presence is
// tracked for settings whose default is true.
func TestExplicitFalseOverridesBooleanDefault(t *testing.T) {
	yaml := strings.Replace(minimalProfile, "  notifications:",
		"  scan:\n    fetch_details_on_listing_change: false\n  notifications:", 1)
	p, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse explicit false: %v", err)
	}
	if p.FetchDetailsOnListingChange() {
		t.Error("explicit false was overwritten by the true default")
	}
}

// TestCryptoAllowTraitIsDefaultedAndRequired ensures auto mode cannot silently
// skip an empty allow list when the rule is supposed to be mandatory.
func TestCryptoAllowTraitIsDefaultedAndRequired(t *testing.T) {
	withAllowList := strings.Replace(minimalProfile, "  notifications:",
		"  crypto:\n    enabled: true\n    mode: auto\n    allowed: [crypto_platform]\n  notifications:", 1)
	p, err := config.Parse([]byte(withAllowList))
	if err != nil {
		t.Fatalf("parse auto crypto profile: %v", err)
	}
	if !p.Crypto.RequireAllowedTrait {
		t.Error("require_allowed_trait defaulted to false in auto mode")
	}

	withoutAllowList := strings.Replace(withAllowList, "    allowed: [crypto_platform]\n", "", 1)
	if _, err := config.Parse([]byte(withoutAllowList)); err == nil || !strings.Contains(err.Error(), "crypto.allowed is empty") {
		t.Errorf("empty required allow list error = %v, want a validation error", err)
	}
}

// TestFlatProfileShapeIsAccepted verifies a profile without the outer key still
// loads, since both shapes are in use.
func TestFlatProfileShapeIsAccepted(t *testing.T) {
	flat := `
name: flat
access:
  max_reputation_points: 50
  kyc_required: no
notifications:
  alert_on_new_programs: true
  new_program_window: 24h
  change_windows:
    default: 72h
`
	p, err := config.Parse([]byte(flat))
	if err != nil {
		t.Fatalf("a flat profile was rejected: %v", err)
	}
	if p.Name != "flat" || p.Access.MaxReputationPoints != 50 {
		t.Errorf("flat profile = %+v, want name flat and a ceiling of 50", p)
	}
}

// TestUnknownKeyIsRejected verifies a misspelled policy key fails loudly.
//
// A silently ignored key is how a filter quietly stops working, and the whole
// point of configuration-driven policy is defeated if a typo can disable it.
func TestUnknownKeyIsRejected(t *testing.T) {
	bad := minimalProfile + "\n  completely_made_up_key: true\n"
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("an unknown configuration key was accepted")
	}
	if !strings.Contains(err.Error(), "completely_made_up_key") {
		t.Errorf("error = %v, want it to name the offending key", err)
	}
}

// TestInvalidEnumValuesAreRejected verifies enum values are validated.
func TestInvalidEnumValuesAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantSub string
	}{
		{
			name:    "unknown crypto mode",
			mutate:  func(s string) string { return s + "\n  crypto:\n    enabled: true\n    mode: sideways\n" },
			wantSub: "crypto.mode",
		},
		{
			name:    "unknown crypto trait",
			mutate:  func(s string) string { return s + "\n  crypto:\n    allowed: [not_a_real_trait]\n" },
			wantSub: "not_a_real_trait",
		},
		{
			name:    "unknown program state",
			mutate:  func(s string) string { return s + "\n  program_states:\n    allowed: [vibing]\n" },
			wantSub: "vibing",
		},
		{
			name: "unknown severity",
			mutate: func(s string) string {
				return strings.Replace(s, "alert_on_new_programs: true", "alert_on_new_programs: true\n    min_severity: extreme", 1)
			},
			wantSub: "min_severity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(tc.mutate(minimalProfile)))
			if err == nil {
				t.Fatal("an invalid value was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestInvalidDurationsAreRejected verifies a bare number cannot be used where a
// duration is expected, since a forgotten unit is a silent 0.
func TestInvalidDurationsAreRejected(t *testing.T) {
	for _, bad := range []string{"request_timeout: 30", "request_timeout: soon"} {
		_, err := config.Parse([]byte(strings.Replace(minimalProfile,
			"  notifications:", "  scan:\n    "+bad+"\n  notifications:", 1)))
		if err == nil {
			t.Errorf("%q was accepted as a duration", bad)
		}
	}
	p, err := config.Parse([]byte(strings.Replace(minimalProfile,
		"  notifications:", "  scan:\n    request_timeout: 45s\n  notifications:", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if p.ScanDuration("request_timeout") != 45*time.Second {
		t.Errorf("request_timeout = %v, want 45s", p.ScanDuration("request_timeout"))
	}
}

// TestContradictoryConfigurationIsRejected verifies combinations that would
// silently disable a filter are refused.
func TestContradictoryConfigurationIsRejected(t *testing.T) {
	t.Run("contradictory target domains", func(t *testing.T) {
		bad := minimalProfile + "\n  target_domains:\n    included: [api]\n    excluded: [api]\n"
		if _, err := config.Parse([]byte(bad)); err == nil {
			t.Error("a domain in both lists was accepted")
		}
	})

	t.Run("inert crypto allow list", func(t *testing.T) {
		// An allow list that is present but not required would have no effect,
		// while appearing to filter.
		bad := minimalProfile +
			"\n  crypto:\n    enabled: true\n    mode: auto\n" +
			"    require_allowed_trait: false\n    allowed: [crypto_platform]\n"
		_, err := config.Parse([]byte(bad))
		if err == nil {
			t.Fatal("a present but inert allow list was accepted")
		}
		if !strings.Contains(err.Error(), "no effect") {
			t.Errorf("error = %v, want it to explain that the list is inert", err)
		}
	})

	t.Run("no alert triggers", func(t *testing.T) {
		bad := minimalProfile + "\n  notifications:\n    alert_on_new_programs: false\n"
		if _, err := config.Parse([]byte(bad)); err == nil {
			t.Error("a profile that can never alert was accepted")
		}
	})

	t.Run("no enabled source", func(t *testing.T) {
		bad := minimalProfile + "\n  sources:\n    hackenproof:\n      enabled: false\n"
		if _, err := config.Parse([]byte(bad)); err == nil {
			t.Error("a profile with no enabled source was accepted")
		}
	})
}

// TestNegativeBoundsAreRejected verifies nonsensical limits fail rather than
// silently matching nothing or everything.
func TestNegativeBoundsAreRejected(t *testing.T) {
	for _, bad := range []string{
		"max_reputation_points: -1",
		"max_submission_fee_usd: -5",
		"max_per_scan: -1",
		"max_retries: -1",
		"max_concurrent: -1",
	} {
		_, err := config.Parse([]byte(strings.Replace(minimalProfile,
			"  notifications:", "  scan:\n    "+bad+"\n  notifications:", 1)))
		if err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// TestPlatformsMapEnablesSources verifies the platforms shorthand is honoured,
// and that a profile which turns every source off is refused rather than
// silently scanning nothing.
func TestPlatformsMapEnablesSources(t *testing.T) {
	on, err := config.Parse([]byte(minimalProfile + "\n  platforms:\n    hackenproof: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(on.EnabledSources()) != 1 || on.EnabledSources()[0] != "hackenproof" {
		t.Errorf("sources = %v, want hackenproof enabled", on.EnabledSources())
	}

	off, err := config.Parse([]byte(minimalProfile + "\n  platforms:\n    hackenproof: false\n"))
	if err == nil {
		t.Errorf("a profile with every source disabled was accepted: %v", off.EnabledSources())
	}
}

// TestEveryProblemIsReported verifies validation collects all failures rather
// than stopping at the first, so a misconfigured profile is fixed in one pass.
func TestEveryProblemIsReported(t *testing.T) {
	// A malformed type aborts YAML decoding immediately with a clear message, so
	// this covers the problems the validator collects itself.
	bad := `
profile:
  access:
    max_reputation_points: -1
    kyc_required: no
  crypto:
    mode: sideways
    allowed: [nonsense_trait]
  program_states:
    allowed: [vibing]
  notifications:
    alert_on_new_programs: false
`
	_, err := config.Parse([]byte(bad))
	if err == nil {
		t.Fatal("an invalid profile was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"name", "max_reputation_points", "mode", "nonsense_trait", "vibing"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
	if lines := strings.Count(msg, "\n"); lines < 4 {
		t.Errorf("error reports %d problems, want several:\n%s", lines, msg)
	}
}

// TestMissingProfileFileIsReported clearly.
func TestMissingProfileFileIsReported(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("a missing profile was accepted")
	}
	if !strings.Contains(err.Error(), "absent.yaml") {
		t.Errorf("error = %v, want it to name the missing file", err)
	}
}

// TestEmptyProfileIsReported verifies an empty document fails rather than
// yielding a profile that silently matches nothing.
func TestEmptyProfileIsReported(t *testing.T) {
	if _, err := config.Parse([]byte("")); err == nil {
		t.Error("an empty profile was accepted")
	}
	if _, err := config.Parse(nil); err == nil {
		t.Error("a nil profile was accepted")
	}
}

// TestProfileIsReadableFromDisk verifies Load and Parse agree.
func TestProfileIsReadableFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte(minimalProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
