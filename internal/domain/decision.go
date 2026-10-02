package domain

import (
	"fmt"
	"sort"
	"strings"
)

// CheckOutcome is the result of one independently evaluated policy requirement.
type CheckOutcome string

const (
	// CheckPass means the requirement was satisfied and positively observed.
	CheckPass CheckOutcome = "pass"
	// CheckFail means the requirement was evaluated and violated.
	CheckFail CheckOutcome = "fail"
	// CheckUnknown means the requirement could not be evaluated because the
	// underlying fact is unknown. It is not a pass, and it is not the same
	// thing as a failure.
	CheckUnknown CheckOutcome = "unknown"
	// CheckSkipped means the requirement did not apply to this program.
	CheckSkipped CheckOutcome = "skipped"
)

// PolicyCheck records one independently evaluated requirement.
//
// Every requirement produces exactly one of these. Nothing about eligibility is
// decided implicitly: a decision is always reconstructible from its checks.
type PolicyCheck struct {
	// ID is a stable machine-readable check identifier, e.g. "access.reputation".
	ID string `json:"id"`

	// Requirement is the human-readable statement of what was required.
	Requirement string `json:"requirement"`

	// Outcome is the verdict.
	Outcome CheckOutcome `json:"outcome"`

	// Observed renders the fact that was actually found, e.g.
	// "150 reputation points".
	Observed string `json:"observed,omitempty"`

	// Expected renders the configured bound, e.g. "<= 80 reputation points".
	Expected string `json:"expected,omitempty"`

	// Detail adds context for failures and unknowns.
	Detail string `json:"detail,omitempty"`
}

// Reason renders one human-readable explanation line for this check.
//
// Observed states what was found and Expected states the bound it was judged
// against. When both are present the bound becomes a parenthetical, which reads
// as a complete note rather than as two fragments run together.
func (c PolicyCheck) Reason() string {
	switch c.Outcome {
	case CheckPass:
		switch {
		case c.Observed != "" && c.Expected != "":
			return c.Observed + " (" + c.Expected + ")"
		case c.Observed != "":
			return c.Observed
		default:
			return c.Requirement + ": satisfied"
		}
	case CheckFail:
		switch {
		case c.Observed != "" && c.Expected != "":
			return c.Observed + ", which does not meet " + c.Expected
		case c.Observed != "":
			return c.Observed + ", which does not meet " + c.Requirement
		default:
			return c.Requirement + ": failed"
		}
	case CheckUnknown:
		if c.Detail != "" {
			return c.Requirement + " is unknown: " + c.Detail
		}
		return c.Requirement + " is unknown"
	default:
		return c.Requirement + ": not applicable"
	}
}

// EligibilityDecision is the structured, reproducible verdict for one program
// against one profile.
//
// The zero value is not eligible: an unevaluated program must never look
// approved.
type EligibilityDecision struct {
	// Eligible is true only when every required check passed.
	Eligible bool `json:"eligible"`

	// Checks holds every evaluated requirement, in evaluation order.
	Checks []PolicyCheck `json:"checks"`

	// Reasons are the human-readable explanations, derived from Checks.
	Reasons []string `json:"reasons"`

	// Blockers are the checks that prevent eligibility, in evaluation order.
	Blockers []PolicyCheck `json:"blockers,omitempty"`

	// Quarantined is true when the program was held back because the source
	// data could not be trusted, rather than because it was judged irrelevant.
	Quarantined bool `json:"quarantined,omitempty"`

	// ProfileID identifies the profile that produced this decision.
	ProfileID string `json:"profile_id,omitempty"`

	// DecidedAt is when the decision was produced.
	DecidedAt string `json:"decided_at,omitempty"`
}

// HasUnknown reports whether any required check could not be evaluated.
func (d EligibilityDecision) HasUnknown() bool {
	for _, c := range d.Checks {
		if c.Outcome == CheckUnknown {
			return true
		}
	}
	return false
}

// Passed returns the checks that passed, in evaluation order.
func (d EligibilityDecision) Passed() []PolicyCheck { return filterChecks(d.Checks, CheckPass) }

// Unknown returns the checks that could not be evaluated.
func (d EligibilityDecision) Unknown() []PolicyCheck { return filterChecks(d.Checks, CheckUnknown) }

func filterChecks(in []PolicyCheck, want CheckOutcome) []PolicyCheck {
	out := make([]PolicyCheck, 0, len(in))
	for _, c := range in {
		if c.Outcome == want {
			out = append(out, c)
		}
	}
	return out
}

// newDecision accumulates checks while keeping reasons and blockers in sync.
//
// Keeping the three collections derived from one ordered check list is what
// makes a decision explainable: reasons can never drift from the checks that
// produced them.
type decisionBuilder struct {
	profileID string
	checks    []PolicyCheck
}

func newDecision(profileID string) *decisionBuilder {
	return &decisionBuilder{profileID: profileID}
}

func (b *decisionBuilder) add(c PolicyCheck) {
	b.checks = append(b.checks, c)
}

func (b *decisionBuilder) pass(id, requirement, observed, expected string) {
	b.add(PolicyCheck{ID: id, Requirement: requirement, Outcome: CheckPass, Observed: observed, Expected: expected})
}

func (b *decisionBuilder) fail(id, requirement, observed, expected, detail string) {
	b.add(PolicyCheck{ID: id, Requirement: requirement, Outcome: CheckFail, Observed: observed, Expected: expected, Detail: detail})
}

func (b *decisionBuilder) unknown(id, requirement, detail string) {
	b.add(PolicyCheck{ID: id, Requirement: requirement, Outcome: CheckUnknown, Detail: detail})
}

func (b *decisionBuilder) skip(id, requirement, detail string) {
	b.add(PolicyCheck{ID: id, Requirement: requirement, Outcome: CheckSkipped, Detail: detail})
}

// build finalizes the decision.
//
// Eligibility is defined as "no failed and no unknown required checks". Unknown
// facts therefore block approval, which is the whole point: an unparsed field
// must never read as an absent requirement.
func (b *decisionBuilder) build(now string, quarantined bool) EligibilityDecision {
	d := EligibilityDecision{
		Checks:      append([]PolicyCheck(nil), b.checks...),
		ProfileID:   b.profileID,
		DecidedAt:   now,
		Quarantined: quarantined,
	}
	d.Reasons = make([]string, 0, len(b.checks))
	d.Blockers = nil
	for _, c := range b.checks {
		if c.Outcome != CheckSkipped {
			d.Reasons = append(d.Reasons, c.Reason())
		}
		if c.Outcome == CheckFail || c.Outcome == CheckUnknown {
			d.Blockers = append(d.Blockers, c)
		}
	}
	d.Eligible = len(d.Blockers) == 0 && !quarantined
	return d
}

// ReasonSummary renders a compact one-line summary suitable for table output.
func (d EligibilityDecision) ReasonSummary() string {
	if d.Eligible {
		return fmt.Sprintf("eligible (%d checks passed)", len(d.Passed()))
	}
	if len(d.Blockers) == 0 {
		return "not eligible"
	}
	parts := make([]string, 0, len(d.Blockers))
	for _, b := range d.Blockers {
		parts = append(parts, b.ID+"="+string(b.Outcome))
	}
	return "not eligible (" + strings.Join(parts, ", ") + ")"
}

// CheckByID returns the check with the given ID.
func (d EligibilityDecision) CheckByID(id string) (PolicyCheck, bool) {
	for _, c := range d.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return PolicyCheck{}, false
}

// sortChecks orders checks by ID for stable presentation.
func sortChecks(cs []PolicyCheck) {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
}
