package policy_test

import (
	"strings"
	"testing"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/policy"
)

// withPOCStance returns baseProfile with an explicit poc_required value.
func withPOCStance(t *testing.T, stance string) string {
	t.Helper()
	return strings.Replace(baseProfile,
		"    kyc_required: no",
		"    kyc_required: no\n    poc_required: "+stance, 1)
}

// A profile that refuses PoC requirements rejects a program that demands one.
// Before the access.poc check existed, a PoC demand was not a rejection rule at
// all: 208 of 324 shipped programs carry one, and all of them sailed through.
func TestPOCRefusalRejectsPOCRequired(t *testing.T) {
	p := newProgram()
	if p.POC != domain.TriYes {
		t.Fatalf("test setup: base program must require a PoC, got %v", p.POC)
	}
	d := decide(t, withPOCStance(t, "no"), p)
	if d.Eligible {
		t.Fatal("a PoC-required program is eligible under poc_required: no")
	}
	found := false
	for _, c := range d.Blockers {
		if strings.Contains(c.ID, "access.poc") || strings.Contains(c.Reason(), "PoC") {
			found = true
		}
	}
	if !found {
		t.Errorf("no PoC blocker recorded; blockers: %+v", d.Blockers)
	}
}

// The default stance is acceptance: profiles written before the setting existed
// must not silently narrow. This pins the asymmetry with KYC, which defaults to
// refusal, deliberately.
func TestPOCDefaultsToAcceptance(t *testing.T) {
	d := decide(t, baseProfile, newProgram())
	if !d.Eligible {
		t.Fatalf("base program must stay eligible without poc_required set; blockers: %+v", d.Blockers)
	}
	found := false
	for _, c := range d.Checks {
		if c.ID == policy.CheckPOC && c.Outcome == domain.CheckPass {
			found = true
		}
	}
	if !found {
		t.Errorf("no passing access.poc check recorded; checks: %+v", d.Checks)
	}
}

// An explicit acceptance admits a PoC-required program.
func TestPOCAcceptanceAdmitsPOCRequired(t *testing.T) {
	d := decide(t, withPOCStance(t, "yes"), newProgram())
	if !d.Eligible {
		t.Fatalf("PoC-required program must be eligible under poc_required: yes; blockers: %+v", d.Blockers)
	}
}

// A program that does not demand a PoC passes under either stance.
func TestPOCNotRequiredPassesUnderRefusal(t *testing.T) {
	p := newProgram(func(p *domain.Program) { p.POC = domain.TriNo })
	d := decide(t, withPOCStance(t, "no"), p)
	if !d.Eligible {
		t.Fatalf("PoC-free program must be eligible under poc_required: no; blockers: %+v", d.Blockers)
	}
}

// An unreadable PoC requirement blocks by default and opts in explicitly,
// mirroring every other access gate.
func TestPOCUnknownBlocksByDefault(t *testing.T) {
	p := newProgram(func(p *domain.Program) { p.POC = domain.TriUnknown })
	d := decide(t, baseProfile, p)
	if d.Eligible {
		t.Fatal("an unreadable PoC requirement must not be eligible by default")
	}
	accepting := strings.Replace(baseProfile,
		"    accept_unknown_access_gates: false",
		"    accept_unknown_access_gates: true", 1)
	if d := decide(t, accepting, p); !d.Eligible {
		t.Fatalf("accept_unknown_access_gates must opt into unknown PoC; blockers: %+v", d.Blockers)
	}
}

// A partially understood record is not a fully understood one. Under the
// default profile it must block, exactly like a low-confidence record; the
// opt-in covers both. Only 8 of 324 shipped programs are partial, so this is a
// precision gain, not a channel cut.
func TestPartialParseIsQuarantinedByDefault(t *testing.T) {
	p := newProgram(func(p *domain.Program) { p.ParseConfidence = domain.ConfidencePartial })
	d := decide(t, baseProfile, p)
	if d.Eligible {
		t.Fatal("a partially understood program must not be eligible by default")
	}
	found := false
	for _, c := range d.Blockers {
		if strings.Contains(c.ID, "data.parse_trust") {
			found = true
		}
	}
	if !found {
		t.Errorf("no parse-trust blocker recorded; blockers: %+v", d.Blockers)
	}
}

// Eligibility is decided by blockers, not by counting passes: a decision with
// no blockers is eligible and anything else is not.
func TestEligibilityMeansNoBlockers(t *testing.T) {
	if d := decide(t, baseProfile, newProgram()); !d.Eligible || len(d.Blockers) != 0 {
		t.Fatalf("base program must be cleanly eligible: %+v", d)
	}
}

// The parse-state opt-in covers partial records as well as low-confidence ones.
func TestPartialParseOptIn(t *testing.T) {
	accepting := strings.Replace(baseProfile,
		"    accept_unknown_parse_state: false",
		"    accept_unknown_parse_state: true", 1)
	p := newProgram(func(p *domain.Program) { p.ParseConfidence = domain.ConfidencePartial })
	if d := decide(t, accepting, p); !d.Eligible {
		t.Fatalf("accept_unknown_parse_state must opt into partial records; blockers: %+v", d.Blockers)
	}
}
