package policy

import (
	"github.com/eadeshina/hunter/internal/domain"
)

// builder accumulates checks and derives the final decision from them.
//
// Keeping reasons and blockers derived from a single ordered check list is what
// guarantees that an explanation can never drift from the evaluation that
// produced it.
type builder struct {
	profileID string
	checks    []domain.PolicyCheck
}

func newBuilder(profileID, at string) *builder {
	return &builder{profileID: profileID}
}

func (b *builder) add(c domain.PolicyCheck) { b.checks = append(b.checks, c) }

func (b *builder) pass(id, requirement, observed, expected string) {
	b.add(domain.PolicyCheck{
		ID: id, Requirement: requirement,
		Outcome: domain.CheckPass, Observed: observed, Expected: expected,
	})
}

func (b *builder) fail(id, requirement, observed, expected, detail string) {
	b.add(domain.PolicyCheck{
		ID: id, Requirement: requirement,
		Outcome: domain.CheckFail, Observed: observed, Expected: expected, Detail: detail,
	})
}

func (b *builder) unknown(id, requirement, detail string) {
	b.add(domain.PolicyCheck{
		ID: id, Requirement: requirement,
		Outcome: domain.CheckUnknown, Detail: detail,
	})
}

func (b *builder) skip(id, requirement, detail string) {
	b.add(domain.PolicyCheck{
		ID: id, Requirement: requirement,
		Outcome: domain.CheckSkipped, Detail: detail,
	})
}

// build finalizes the decision.
//
// Eligibility means every required check passed. An unknown check is not a pass,
// so a fact the system could not determine blocks approval. That is the single
// rule that keeps a parser regression from turning into a flood of false
// positives.
func (b *builder) build(profileID, at string) domain.EligibilityDecision {
	d := domain.EligibilityDecision{
		Checks:    append([]domain.PolicyCheck(nil), b.checks...),
		ProfileID: profileID,
		DecidedAt: at,
	}

	d.Reasons = make([]string, 0, len(b.checks))
	for _, c := range b.checks {
		if c.Outcome != domain.CheckSkipped {
			d.Reasons = append(d.Reasons, c.Reason())
		}
		switch c.Outcome {
		case domain.CheckFail, domain.CheckUnknown:
			d.Blockers = append(d.Blockers, c)
		}
	}
	d.Eligible = len(d.Blockers) == 0
	return d
}
