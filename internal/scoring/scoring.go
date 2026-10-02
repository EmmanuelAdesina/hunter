// Package scoring produces a deterministic attention-priority ordering.
//
// This is explicitly not a prediction of vulnerability likelihood, and no
// component claims to estimate exploitability. It is a transparent ordering
// heuristic that helps decide what to read first when several programs qualify.
//
// Two rules govern everything here:
//
//   - Every component is published with its own value and a one-line basis, so
//     the total can always be traced back to observed facts.
//   - Raw inputs stay visible. A competition signal in particular is reported
//     as the number that was observed, never as a conclusion about how many
//     competitors there are.
package scoring

import (
	"fmt"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// component describes one scored signal.
type component struct {
	name string
	// weight is the share of the total this component may contribute. Weights
	// sum to 1 so that the total stays interpretable as a 0-100 blend.
	weight float64
	// value computes the component on a 0-100 scale.
	value func(in input) (int, string)
}

// input is the fact set a component may read.
type input struct {
	program   domain.Program
	decision  domain.EligibilityDecision
	freshness domain.Freshness
	changes   domain.ChangeSet
	profile   *config.Profile
}

// components is the ordered component set.
//
// Order matters only for presentation; the total is weight-based and therefore
// independent of it.
var components = []component{
	{name: "eligibility", weight: 0.25, value: eligibilityFit},
	{name: "freshness", weight: 0.20, value: freshnessScore},
	{name: "surface relevance", weight: 0.20, value: surfaceScore},
	{name: "scope richness", weight: 0.12, value: scopeRichness},
	{name: "change magnitude", weight: 0.10, value: changeMagnitude},
	{name: "low competition", weight: 0.08, value: competitionScore},
	{name: "bounty", weight: 0.05, value: bountyScore},
}

// Scorer computes triage for programs against a profile.
type Scorer struct {
	profile *config.Profile
}

// New builds a scorer.
func New(profile *config.Profile) *Scorer { return &Scorer{profile: profile} }

// Score produces a triage result for one program.
func (s *Scorer) Score(p domain.Program, d domain.EligibilityDecision, f domain.Freshness, cs domain.ChangeSet) domain.Triage {
	in := input{program: p, decision: d, freshness: f, changes: cs, profile: s.profile}

	comps := make([]domain.TriageComponent, 0, len(components))
	total := 0.0
	for _, c := range components {
		v, basis := c.value(in)
		if v < 0 {
			v = 0
		}
		if v > 100 {
			v = 100
		}
		total += float64(v) * c.weight
		comps = append(comps, domain.TriageComponent{
			Name: c.name, Value: v, Weight: c.weight, Basis: basis,
		})
	}
	domain.SortComponents(comps)

	return domain.Triage{
		Total:      int(total + 0.5),
		Components: comps,
		Inputs:     rawInputs(p, f, cs),
	}
}

// eligibilityFit scores how completely the profile matched.
//
// A clean pass scores full marks; a rejection with one blocker scores lower than
// a rejection with many, so that a near miss still ranks above a hopeless
// candidate when the researcher is browsing rather than being paged.
func eligibilityFit(in input) (int, string) {
	total := len(in.decision.Checks)
	if total == 0 {
		return 0, "no checks were evaluated"
	}
	passed := 0
	for _, c := range in.decision.Checks {
		if c.Outcome == domain.CheckPass {
			passed++
		}
	}
	score := passed * 100 / total
	basis := fmt.Sprintf("%d of %d requirements satisfied", passed, total)
	if in.decision.Eligible {
		basis += "; eligible"
	} else {
		basis += fmt.Sprintf("; blocked by %d", len(in.decision.Blockers))
	}
	return score, basis
}

// freshnessScore rewards recency, using the newest available signal.
//
// A program launched three years ago whose API scope was expanded six minutes
// ago must score as fresh. The newest signal wins because that is the change
// that actually creates an opportunity.
func freshnessScore(in input) (int, string) {
	f := in.freshness

	candidates := make([]struct {
		label string
		age   time.Duration
		known bool
	}, 0, 3)

	if f.ScopeChangeAge > 0 {
		candidates = append(candidates, struct {
			label string
			age   time.Duration
			known bool
		}{"scope changed", f.ScopeChangeAge, true})
	}
	if f.RequirementChangeAge > 0 {
		candidates = append(candidates, struct {
			label string
			age   time.Duration
			known bool
		}{"requirements changed", f.RequirementChangeAge, true})
	}
	if f.FirstSeenAge > 0 {
		candidates = append(candidates, struct {
			label string
			age   time.Duration
			known bool
		}{"first seen", f.FirstSeenAge, true})
	}
	if len(candidates) == 0 {
		return 50, "no age information is available"
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.age < best.age {
			best = c
		}
	}

	// The decay window is the configured freshness window; anything at or newer
	// than that scores full marks, and the score decays to zero over roughly ten
	// windows.
	window := in.profile.FreshProgramWindow()
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	if best.age <= window {
		return 100, best.label + " " + domain.HumanizeDuration(best.age)
	}
	over := float64(best.age-window) / float64(10*window)
	score := 100 - int(over*100)
	if score < 0 {
		score = 0
	}
	return score, best.label + " " + domain.HumanizeDuration(best.age)
}

// surfaceScore rewards the surfaces the researcher actually specializes in.
func surfaceScore(in input) (int, string) {
	included := domain.NewTags(in.profile.TargetDomains.Included...)
	if len(included) == 0 {
		return 50, "the profile does not restrict surfaces"
	}
	present := in.program.SurfaceTags.Intersect(included)
	if len(present) == 0 {
		return 0, "no surface of interest is present"
	}

	// Each matching surface contributes, with diminishing returns, so that
	// breadth of attack surface beats repetition of one kind.
	score := 0
	switch len(present) {
	case 1:
		score = 70
	case 2:
		score = 88
	default:
		score = 100
	}
	return score, "matches " + present.Join()
}

// scopeRichness rewards a scope with more distinct assets to work on.
func scopeRichness(in input) (int, string) {
	n := len(in.program.InScopeTargets())
	switch {
	case n == 0:
		return 0, "no in-scope assets"
	case n <= 2:
		return 50, fmt.Sprintf("%d in-scope assets", n)
	case n <= 5:
		return 75, fmt.Sprintf("%d in-scope assets", n)
	case n <= 10:
		return 90, fmt.Sprintf("%d in-scope assets", n)
	default:
		return 100, fmt.Sprintf("%d in-scope assets", n)
	}
}

// changeMagnitude rewards the size of what changed.
func changeMagnitude(in input) (int, string) {
	// Only medium and above severities count; a wording tweak is not an
	// opportunity.
	weighted := 0
	for _, c := range in.changes {
		switch c.Severity {
		case domain.SeverityHigh:
			weighted += 3
		case domain.SeverityMedium:
			weighted++
		}
	}
	if weighted == 0 {
		return 20, "nothing material changed"
	}
	score := weighted * 20
	if score > 100 {
		score = 100
	}
	return score, fmt.Sprintf("%d weighted change events", weighted)
}

// competitionScore rewards a low observed submission count.
//
// The observed count is reported as-is. Submission count is a weak proxy for
// competition - it includes duplicates, invalid reports, and reports from
// researchers who left long ago - so the basis line always names the number
// rather than asserting a level of competition.
func competitionScore(in input) (int, string) {
	if !in.program.SubmittedReportsKnown || in.program.SubmittedReports == nil {
		// Absence is not evidence of low competition, so an unknown count is
		// treated as neutral rather than favourable.
		return 50, "submission count is not published"
	}
	n := *in.program.SubmittedReports
	score := competitionScoreFor(n, in.program.StartedAt, in.freshness.FirstSeenAge)
	return score, fmt.Sprintf("%d submissions reported by the platform", n)
}

// competitionScoreFor maps a submission count onto a 0-100 score.
//
// A very new program with a handful of submissions is the best case. A long
// running program with thousands is the worst. The curve is logarithmic because
// the difference between zero and ten submissions matters far more than the
// difference between one thousand and one thousand one hundred.
func competitionScoreFor(submissions int, startedAt *time.Time, age time.Duration) int {
	if submissions < 0 {
		return 50
	}
	// Logarithmic base 2 decay: 1 -> ~93, 10 -> ~60, 100 -> ~27.
	score := 100 - 7*log2(float64(submissions+1))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// A very young program has not had time to accumulate reports, so a modest
	// count there is less discouraging than the same count on an old program.
	if startedAt != nil || age > 0 {
		programAge := age
		if startedAt != nil {
			programAge = time.Since(*startedAt)
		}
		if programAge < 24*time.Hour && score < 85 {
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	return int(score)
}

// bountyScore rewards a larger stated ceiling.
//
// This is the smallest-weighted signal on purpose. A large bounty is not
// evidence of an easier bug, and over-weighting it would bias the channel
// toward whichever organization pays most.
func bountyScore(in input) (int, string) {
	max := in.program.MaxBountyUSD
	if max == nil {
		return 40, "no bounty ceiling is stated"
	}
	switch {
	case *max <= 0:
		return 40, "no monetary bounty is stated"
	case *max < 500:
		return 50, fmt.Sprintf("ceiling $%.0f", *max)
	case *max < 5000:
		return 70, fmt.Sprintf("ceiling $%.0f", *max)
	case *max < 25000:
		return 85, fmt.Sprintf("ceiling $%.0f", *max)
	default:
		return 100, fmt.Sprintf("ceiling $%.0f", *max)
	}
}

// rawInputs assembles the visible fact set behind the score.
func rawInputs(p domain.Program, f domain.Freshness, cs domain.ChangeSet) domain.TriageInputs {
	material := 0
	for _, c := range cs {
		if c.Severity.AtLeast(domain.SeverityMedium) {
			material++
		}
	}
	inputs := domain.TriageInputs{
		SubmissionCountKnown: p.SubmittedReportsKnown,
		ProgramAgeBasis:      f.ProgramAgeBasis,
		ScopeChangeAge:       f.ScopeChangeAge,
		RequirementChangeAge: f.RequirementChangeAge,
		ScopeSize:            len(p.InScopeTargets()),
		ChangeCount:          material,
		MaxBountyUSD:         p.MaxBountyUSD,
	}
	if p.SubmittedReports != nil {
		v := *p.SubmittedReports
		inputs.SubmittedReports = &v
	}
	if f.ProgramAge > 0 {
		inputs.ProgramAge = f.ProgramAge
	}
	return inputs
}

// log2 computes a base-2 logarithm without importing math at every call site.
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	const ln2 = 0.6931471805599453
	// math.Log is used via a small local helper to keep this file's imports
	// focused on the domain types.
	return log(x) / ln2
}
