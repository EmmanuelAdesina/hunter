package alerts_test

import (
	"strings"
	"testing"

	"github.com/eadeshina/hunter/internal/alerts"
	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// profileWithAlertStates parses the shared test profile with an explicit
// program_states.alert_on_state list.
func profileWithAlertStates(t *testing.T, states string) *config.Profile {
	t.Helper()
	raw := strings.Replace(profileYAML,
		"  program_states:\n    allowed: [live, new]",
		"  program_states:\n    allowed: [live, new]\n    alert_on_state: ["+states+"]", 1)
	p, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	return p
}

// A new live program is silent when the profile only pages for new states.
// program_states.alert_on_state separates "evaluate and track" from "wake the
// researcher": without this gate the setting would be parsed and ignored.
func TestAlertOnStateGatesNewProgram(t *testing.T) {
	got := generator(profileWithAlertStates(t, "new")).Decide(candidate())
	if got != nil {
		t.Fatalf("a live new program alerted despite alert_on_state=[new]: %q", got.Subject)
	}
}

// The same program alerts when its state is listed.
func TestAlertOnStateAllowsListedState(t *testing.T) {
	got := generator(profileWithAlertStates(t, "live, new")).Decide(candidate())
	if got == nil {
		t.Fatal("a live new program did not alert with alert_on_state=[live, new]")
	}
	if got.Kind != domain.AlertNewQualifying {
		t.Errorf("kind = %s, want NEW_QUALIFYING", got.Kind)
	}
}

// A profile written before the setting existed has no list, and no list means
// no gating. Backward compatibility is a property worth pinning: adding a key
// must not retroactively silence profiles that never set it.
func TestEmptyAlertOnStateListAllowsAll(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program.State = domain.StatePaused
	}))
	if got == nil {
		t.Fatal("an empty alert_on_state list must not gate anything")
	}
}

// A reactivation into an unlisted state is silent, even with a fresh interval
// and high severity. The state gate runs before every trigger, not just the
// launch ones.
func TestAlertOnStateGatesReactivation(t *testing.T) {
	build := func(p *config.Profile) *domain.Alert {
		return generator(p).Decide(candidate(func(c *alerts.Candidate) {
			c.Diff = domain.Diff{
				ProgramID: "hackenproof:example",
				Changes: domain.ChangeSet{
					{Kind: domain.ChangeProgramReactivated, Severity: domain.SeverityHigh,
						Direction: domain.DirectionImproved,
						Before:    "paused", After: "live"},
				},
			}
			c.Fresh.LifecycleChange = freshLifecycleChange()
			c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
		}))
	}
	if got := build(profileWithAlertStates(t, "new")); got != nil {
		t.Fatalf("a reactivation into live alerted despite alert_on_state=[new]: %q", got.Subject)
	}
	if got := build(profileWithAlertStates(t, "live, new")); got == nil {
		t.Fatal("a reactivation into a listed state did not alert")
	}
}

// A scope expansion on a program in an unlisted state is silent. Eligibility
// would usually suppress this first, but the candidate carries a hand-built
// eligible decision, so this test isolates the state gate itself.
func TestAlertOnStateGatesScopeExpansion(t *testing.T) {
	got := generator(profileWithAlertStates(t, "new")).Decide(candidate(func(c *alerts.Candidate) {
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{{
				Kind: domain.ChangeAPIAdded, Severity: domain.SeverityMedium,
				Direction: domain.DirectionImproved,
				Field:     "api", Assets: []string{"https://api-v2.example.com"},
			}},
		}
		c.Fresh.ScopeChange = freshScopeChange()
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got != nil {
		t.Fatalf("a scope expansion on a live program alerted despite alert_on_state=[new]: %q", got.Subject)
	}
}

// An unknown lifecycle state can never be shown to be alert-worthy.
func TestAlertOnStateRejectsUnknownState(t *testing.T) {
	got := generator(profileWithAlertStates(t, "live, new")).Decide(candidate(func(c *alerts.Candidate) {
		c.Program.State = domain.StateUnknown
	}))
	if got != nil {
		t.Fatalf("a program of unknown state alerted: %q", got.Subject)
	}
}
