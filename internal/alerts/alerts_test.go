package alerts_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/alerts"
	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const profileYAML = `
profile:
  name: test
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
  target_domains:
    included: [web_application, api, backend, codebase]
  crypto:
    enabled: true
    mode: auto
    require_allowed_trait: true
    allowed: [crypto_platform, exchange, crypto_api, crypto_backend]
    excluded: [smart_contract_only, solidity_only, protocol_consensus]
    dominance_ratio: 0.6
  program_states:
    allowed: [live, new]
  notifications:
    enabled: true
    min_severity: medium
    require_eligible: true
    alert_on_new_programs: true
    new_program_window: 24h
    alert_on_material_change: true
    alert_on_newly_eligible: true
    alert_on_scope_expansion: true
    max_per_scan: 0
    subject_prefix: "[HUNTER]"
`

func profile(t *testing.T) *config.Profile {
	t.Helper()
	p, err := config.Parse([]byte(profileYAML))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	return p
}

func generator(p *config.Profile) *alerts.Generator {
	return alerts.NewGenerator(p, func() time.Time { return fixedNow })
}

// program builds a qualifying program.
func program(mutators ...func(*domain.Program)) domain.Program {
	max := 5000.0
	// Launched three hours ago, comfortably inside the default window, so the
	// baseline program is a qualifying new launch rather than a long-running one.
	started := fixedNow.Add(-3 * time.Hour)
	subs := 12

	p := domain.Program{
		ID:                    "hackenproof:example",
		Source:                "hackenproof",
		Slug:                  "example",
		Name:                  "Crypto Platform X",
		URL:                   "https://hackenproof.com/programs/example",
		State:                 domain.StateLive,
		Reputation:            domain.ReputationGate{Present: domain.TriNo},
		Fee:                   domain.FeeGate{Present: domain.TriNo},
		KYC:                   domain.TriNo,
		POC:                   domain.TriYes,
		MaxBountyUSD:          &max,
		SubmittedReports:      &subs,
		SubmittedReportsKnown: true,
		SurfaceTags:           domain.NewTags("web_application", "api"),
		CapabilityTags:        domain.NewTags("authentication", "user_accounts"),
		CryptoKind:            domain.CryptoPlatform,
		CryptoTraits:          domain.NewTags("crypto_platform", "exchange", "crypto_api"),
		ParseConfidence:       domain.ConfidenceHigh,
		StartedAt:             &started,
		FirstSeenAt:           fixedNow.Add(-8 * time.Minute),
		Targets: domain.Targets{
			{Kind: domain.KindWeb, Identifier: "*.example.com", Label: "Web", InScope: true},
			{Kind: domain.KindAPI, Identifier: "https://api.example.com", Label: "API", InScope: true},
		},
	}
	for _, m := range mutators {
		m(&p)
	}
	p.Finalize()
	return p
}

func eligibleDecision() domain.EligibilityDecision {
	return domain.EligibilityDecision{
		Eligible: true,
		Reasons:  []string{"KYC is not required", "exposes api"},
		Checks: []domain.PolicyCheck{
			{ID: "access.kyc", Requirement: "KYC", Outcome: domain.CheckPass, Observed: "KYC is not required"},
		},
	}
}

// candidate builds a new-program candidate.
func candidate(mutators ...func(*alerts.Candidate)) alerts.Candidate {
	c := alerts.Candidate{
		Program:  program(),
		Decision: eligibleDecision(),
		Diff: domain.Diff{
			ProgramID: "hackenproof:example",
			IsNew:     true,
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeNewProgram, Severity: domain.SeverityHigh, After: "Crypto Platform X",
			}},
		},
		Fresh: domain.Freshness{FirstSeenAge: 8 * time.Minute},
		Triage: domain.Triage{
			Total: 88,
			Components: []domain.TriageComponent{
				{Name: "eligibility", Value: 100, Basis: "all requirements satisfied"},
				{Name: "freshness", Value: 96, Basis: "first seen 8m ago"},
			},
			Inputs: domain.TriageInputs{SubmissionCountKnown: true, SubmittedReports: intPtr(12)},
		},
	}
	for _, m := range mutators {
		m(&c)
	}
	return c
}

func intPtr(n int) *int { return &n }

// TestNewQualifyingProgramAlerts verifies a newly discovered qualifying program
// produces an alert.
func TestNewQualifyingProgramAlerts(t *testing.T) {
	got := generator(profile(t)).Decide(candidate())
	if got == nil {
		t.Fatal("no alert for a new qualifying program")
	}
	if got.Kind != domain.AlertNewQualifying {
		t.Errorf("kind = %s, want NEW_QUALIFYING", got.Kind)
	}
	if got.Fingerprint == "" {
		t.Error("alert has no fingerprint, so it could not be deduplicated")
	}
}

// TestFingerprintIsStableAcrossScans verifies the same condition yields the same
// fingerprint. Without this, every five-minute run would send another email for
// an unchanged program.
func TestFingerprintIsStableAcrossScans(t *testing.T) {
	g := generator(profile(t))
	first := g.Decide(candidate())
	second := g.Decide(candidate())
	if first == nil || second == nil {
		t.Fatal("expected alerts")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Errorf("fingerprint changed between identical scans: %s vs %s",
			first.ShortFingerprint(), second.ShortFingerprint())
	}
}

// TestFingerprintDiffersByCondition verifies distinct conditions are distinct
// alerts, so a real change is not suppressed by an earlier one.
func TestFingerprintDiffersByCondition(t *testing.T) {
	g := generator(profile(t))

	isNew := g.Decide(candidate())
	if isNew == nil {
		t.Fatal("no alert for a new program")
	}

	apiAdded := g.Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeAPIAdded, Severity: domain.SeverityMedium,
				Field: "api", Assets: []string{"https://api-v2.example.com"},
			}},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if apiAdded == nil {
		t.Fatal("no alert for a scope expansion")
	}
	if apiAdded.Fingerprint == isNew.Fingerprint {
		t.Error("a scope expansion collided with the new-program alert")
	}
}

// TestIneligibleProgramIsSilent verifies an ineligible program produces nothing
// while the profile requires eligibility.
func TestIneligibleProgramIsSilent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Decision.Eligible = false
		c.Decision.Reasons = []string{"KYC is required"}
	}))
	if got != nil {
		t.Errorf("an ineligible program raised %s: %q", got.Kind, got.Subject)
	}
}

// TestNewlyEligibleAlerts verifies a previously rejected program alerts when it
// becomes acceptable, such as after a reputation requirement is lowered.
func TestNewlyEligibleAlerts(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeReputationChanged, Severity: domain.SeverityMedium,
				Before: "150 reputation points", After: "50 reputation points",
			}},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: false}
	}))
	if got == nil {
		t.Fatal("no alert for a program that became eligible")
	}
	if got.Kind != domain.AlertNewlyEligible {
		t.Errorf("kind = %s, want NEWLY_ELIGIBLE", got.Kind)
	}
}

// TestStillRejectedIsSilent verifies a rejected program that remains rejected
// stays silent even when it changes.
func TestStillRejectedIsSilent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Decision.Eligible = false
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeTargetAdded, Severity: domain.SeverityMedium,
				Assets: []string{"https://new.example.com"},
			}},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: false}
	}))
	if got != nil {
		t.Errorf("a still-rejected program alerted: %q", got.Subject)
	}
}

// TestNoChangeIsSilent verifies an unchanged program does not alert.
func TestNoChangeIsSilent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{ProgramID: "hackenproof:example"}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got != nil {
		t.Errorf("an unchanged program alerted: %q", got.Subject)
	}
}

// TestLowSeverityChangeIsSilent verifies the severity floor is respected, so a
// wording tweak cannot produce an email.
func TestLowSeverityChangeIsSilent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeSubmissionsChanged, Severity: domain.SeverityLow,
				Before: "11 submissions", After: "12 submissions",
			}},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got != nil {
		t.Errorf("a low-severity change alerted: %q", got.Subject)
	}
}

// TestReactivationAlerts verifies a reopened program alerts, since a reopened
// program is a fresh window other researchers have not seen.
func TestReactivationAlerts(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{
				{Kind: domain.ChangeProgramReactivated, Severity: domain.SeverityHigh,
					Before: "paused", After: "live"},
			},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got == nil {
		t.Fatal("no alert for a reactivated program")
	}
}

// TestScopeRemovalDoesNotAlert verifies losing scope is not treated as an
// opening.
func TestScopeRemovalDoesNotSilent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeTargetRemoved, Severity: domain.SeverityLow,
				Assets: []string{"https://legacy.example.com"},
			}},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got != nil {
		t.Errorf("a scope removal alerted: %q", got.Subject)
	}
}

// TestDisabledNotificationsSuppressEverything verifies the kill switch.
func TestDisabledNotificationsSuppressEverything(t *testing.T) {
	p := profile(t)
	p.Notifications.Enabled = false
	if got := generator(p).Decide(candidate()); got != nil {
		t.Errorf("an alert was raised with notifications disabled: %q", got.Subject)
	}
}

// TestSubjectFormat verifies the subject carries the information needed to
// triage from a lock screen.
func TestSubjectFormat(t *testing.T) {
	got := generator(profile(t)).Decide(candidate())
	if got == nil {
		t.Fatal("no alert")
	}
	if !strings.HasPrefix(got.Subject, "[HUNTER]") {
		t.Errorf("subject lacks the configured prefix: %q", got.Subject)
	}
	for _, want := range []string{"NEW MATCH", "Crypto Platform X", "API/Web"} {
		if !strings.Contains(got.Subject, want) {
			t.Errorf("subject = %q, want it to contain %q", got.Subject, want)
		}
	}
	if strings.Contains(got.Subject, "—  —") || strings.HasSuffix(got.Subject, "—") {
		t.Errorf("subject has a dangling separator: %q", got.Subject)
	}
	if len(got.Subject) > 160 {
		t.Errorf("subject is %d characters; it must stay readable on a phone", len(got.Subject))
	}
}

// TestBodyContent verifies the body carries access facts, surface, and the
// reasoning.
func TestBodyContent(t *testing.T) {
	got := generator(profile(t)).Decide(candidate())
	if got == nil {
		t.Fatal("no alert")
	}
	body := got.Body

	for _, want := range []string{
		"NEW QUALIFYING OPPORTUNITY",
		"Program:",
		"Access:",
		"Attack surface:",
		"Crypto classification:",
		"Competition (reported by platform):",
		"12 submissions",
		"Why this matched:",
		"KYC is not required",
		"https://hackenproof.com/programs/example",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	// The program description must not be inlined: it would bury the signal.
	if strings.Contains(body, "In Scope Vulnerabilities") {
		t.Error("body inlined the source's own prose")
	}
}

// TestBodyMarksUnknownFacts verifies an unknown access fact is rendered as
// unknown rather than as an absent requirement.
func TestBodyMarksUnknownFacts(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(func(p *domain.Program) { p.KYC = domain.TriUnknown })
	}))
	if got == nil {
		t.Fatal("no alert")
	}
	if !strings.Contains(got.Body, "UNKNOWN") {
		t.Errorf("body does not mark the unknown KYC requirement:\n%s", got.Body)
	}
	if strings.Contains(got.Body, "✓") && strings.Contains(got.Body, "kyc: ") &&
		strings.Contains(got.Body, "kyc: ✓") {
		t.Error("an unknown KYC requirement was rendered with a checkmark")
	}
}

// TestBodyIsMobileFriendly verifies lines stay short enough to scan.
func TestBodyIsMobileFriendly(t *testing.T) {
	got := generator(profile(t)).Decide(candidate())
	if got == nil {
		t.Fatal("no alert")
	}
	for _, line := range strings.Split(got.Body, "\n") {
		if len(line) > 120 {
			t.Errorf("line exceeds 120 characters (%d): %q", len(line), line)
		}
	}
}

// TestRenderingIsDeterministic verifies the same input renders identically,
// which is what makes the alert body assertable and the delivery idempotent.
func TestRenderingIsDeterministic(t *testing.T) {
	g := generator(profile(t))
	first := g.Decide(candidate())
	subject, body, htmlBody := alerts.Render(candidate(), profile(t), fixedNow)

	if first.Subject != subject {
		t.Errorf("subject differs:\n %q\n %q", first.Subject, subject)
	}
	if first.Body != body {
		t.Error("body differs between two identical renderings")
	}
	if first.HTMLBody != htmlBody {
		t.Error("html body differs between two identical renderings")
	}
}

// TestTriageComponentsAreExposed verifies the score is published in parts, not
// as an opaque number.
func TestTriageComponentsAreExposed(t *testing.T) {
	got := generator(profile(t)).Decide(candidate())
	if got == nil {
		t.Fatal("no alert")
	}
	if len(got.Triage.Components) == 0 {
		t.Fatal("triage exposes no components")
	}
	for _, comp := range got.Triage.Components {
		if comp.Basis == "" {
			t.Errorf("component %q has no stated basis", comp.Name)
		}
	}
	if !strings.Contains(got.Body, "Attention priority") {
		t.Error("body does not label the triage value")
	}
	if !strings.Contains(got.Body, "not a success estimate") {
		t.Error("body does not disclaim the score as a likelihood estimate")
	}
}

// TestPerScanCap verifies the alert cap keeps the channel usable during a bulk
// import, and reports what it dropped.
func TestPerScanCap(t *testing.T) {
	p := profile(t)
	p.Notifications.MaxPerScan = 3
	g := generator(p)

	var generated []domain.Alert
	for i := 0; i < 10; i++ {
		alerts.SortByPriority(nil)
		a := g.Decide(candidate(func(c *alerts.Candidate) {
			c.Program.Name = "Program " + string(rune('A'+i))
			c.Program.ID = "hackenproof:p" + string(rune('a'+i))
			c.Program.Finalize()
			c.Triage.Total = 90 - i
		}))
		if a != nil {
			generated = append(generated, *a)
		}
	}
	capped, dropped := g.CapAlerts(generated)
	if len(capped) != 3 {
		t.Errorf("capped to %d alerts, want 3", len(capped))
	}
	if dropped != len(generated)-3 {
		t.Errorf("dropped = %d, want %d", dropped, len(generated)-3)
	}
	// The highest priority must survive the cap.
	if capped[0].Triage.Total != 90 {
		t.Errorf("first retained alert has priority %d, want the highest (90)", capped[0].Triage.Total)
	}
}

// TestPriorityOrderingIsStable verifies sorting does not depend on input order.
func TestPriorityOrderingIsStable(t *testing.T) {
	g := generator(profile(t))
	mk := func(name string, priority int) domain.Alert {
		a := g.Decide(candidate(func(c *alerts.Candidate) {
			c.Program.Name = name
			c.Program.ID = "hackenproof:" + name
			c.Program.Finalize()
			c.Triage.Total = priority
		}))
		if a == nil {
			t.Fatalf("no alert for %s", name)
		}
		return *a
	}
	a, b, c := mk("low", 40), mk("high", 95), mk("mid", 70)

	forward := []domain.Alert{a, b, c}
	reversed := []domain.Alert{c, b, a}
	alerts.SortByPriority(forward)
	alerts.SortByPriority(reversed)

	for i := range forward {
		if forward[i].ProgramID != reversed[i].ProgramID {
			t.Errorf("ordering differs at %d: %s vs %s", i, forward[i].ProgramID, reversed[i].ProgramID)
		}
	}
	if forward[0].ProgramID != "hackenproof:high" {
		t.Errorf("highest priority is not first: %s", forward[0].ProgramID)
	}
}

// TestAccessBlockMarksUnknownFacts verifies an unreadable gate is rendered
// distinctly from a satisfied one.
//
// This is the safety property made visible: a reader must be able to tell at a
// glance that a gate could not be determined, rather than seeing a uniform list
// of checkmarks and assuming everything is clear.
func TestAccessBlockMarksUnknownFacts(t *testing.T) {
	allKnown := generator(profile(t)).Decide(candidate())
	if allKnown == nil {
		t.Fatal("no alert")
	}
	for _, line := range accessLines(allKnown.Body) {
		if strings.Contains(line, "UNKNOWN") {
			t.Errorf("line %q reports unknown although every gate is known", line)
		}
		if !strings.Contains(line, "✓") {
			t.Errorf("line %q has no marker: %q", line, line)
		}
	}

	unknowns := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(func(p *domain.Program) {
			p.Reputation = domain.ReputationGate{Present: domain.TriUnknown}
			p.KYC = domain.TriUnknown
			p.Fee = domain.FeeGate{Present: domain.TriUnknown}
			p.POC = domain.TriUnknown
		})
	}))
	if unknowns == nil {
		t.Fatal("no alert")
	}
	unknownCount := 0
	for _, line := range accessLines(unknowns.Body) {
		if strings.Contains(line, "UNKNOWN") {
			unknownCount++
			if strings.Contains(line, "✓") {
				t.Errorf("an unknown gate is rendered with a checkmark: %q", line)
			}
			continue
		}
		if !strings.Contains(line, "✓") {
			t.Errorf("line %q has no marker: %q", line, line)
		}
	}
	if unknownCount != 4 {
		t.Errorf("marked %d unknown gates, want 4", unknownCount)
	}
}

// accessLines returns the gate lines of the Access block.
//
// The bounty ceiling is skipped: it is a fact about the program, not a gate the
// researcher has to pass, and so it carries no marker by design.
func accessLines(body string) []string {
	var out []string
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "Access:" {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.TrimSpace(line) == "" {
				break
			}
			if strings.Contains(line, "Bounty ceiling") {
				continue
			}
			out = append(out, line)
		}
	}
	return out
}
