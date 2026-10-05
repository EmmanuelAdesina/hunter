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
	"sort"
	"strings"
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
	windows   []domain.OpportunityWindow
	// now is the clock every age is measured against. It is supplied by the
	// caller so that a score is reproducible and so that an interval cannot be
	// rendered against a different moment than it was scored against.
	now time.Time
}

// components is the ordered component set.
//
// Order matters only for presentation; the total is weight-based and therefore
// independent of it.
var components = []component{
	{name: "eligibility", weight: 0.22, value: eligibilityFit},
	{name: "freshness", weight: 0.20, value: freshnessScore},
	{name: "surface relevance", weight: 0.18, value: surfaceScore},
	{name: "scope richness", weight: 0.10, value: scopeRichness},
	{name: "change magnitude", weight: 0.10, value: changeMagnitude},
	{name: "access delta", weight: 0.08, value: accessDeltaScore},
	{name: "low competition", weight: 0.04, value: competitionScore},
	{name: "post-change competition", weight: 0.04, value: postChangeCompetitionScore},
	{name: "bounty", weight: 0.04, value: bountyScore},
}

// Scorer computes triage for programs against a profile.
type Scorer struct {
	profile *config.Profile
	now     func() time.Time
}

// New builds a scorer.
//
// The clock is injectable so that an interval's age range is identical between
// a score and the alert that reports it.
func New(profile *config.Profile, now ...func() time.Time) *Scorer {
	clock := time.Now
	if len(now) > 0 && now[0] != nil {
		clock = now[0]
	}
	return &Scorer{profile: profile, now: clock}
}

// Score produces triage for one program without persisted opportunity windows.
func (s *Scorer) Score(p domain.Program, d domain.EligibilityDecision, f domain.Freshness, cs domain.ChangeSet) domain.Triage {
	return s.ScoreWithWindows(p, d, f, cs, nil)
}

// ScoreWithWindows adds stored opportunity-window evidence to the same single
// attention score. Current transition evidence in cs takes precedence over an
// older window, so the count baseline is zero movement when the transition opens.
func (s *Scorer) ScoreWithWindows(
	p domain.Program,
	d domain.EligibilityDecision,
	f domain.Freshness,
	cs domain.ChangeSet,
	windows []domain.OpportunityWindow,
) domain.Triage {
	in := input{
		program: p, decision: d, freshness: f, changes: cs,
		profile: s.profile, windows: windows, now: s.now(),
	}

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
		Inputs:     rawInputs(in),
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

// freshCandidate is one recency signal considered by freshnessScore.
type freshCandidate struct {
	label string
	age   time.Duration
	// interval is set when the signal came from a change interval, and is used
	// to render the basis as a bounded range rather than a point.
	interval domain.ObservationInterval
}

// basis renders the candidate's evidence for the component line.
//
// A change-derived candidate prints its whole age range, so the published number
// is never more precise than the observation behind it.
func (c freshCandidate) basis(now time.Time) string {
	if c.interval.Known() {
		return c.interval.Humanize(now)
	}
	return domain.HumanizeDuration(c.age)
}

// freshnessScore rewards recency, using the newest available signal.
//
// A program launched three years ago whose API scope was expanded six minutes
// ago must score as fresh. The newest signal wins because that is the change
// that actually creates an opportunity.
//
// Change signals arrive as intervals, so "how old is the change" is a range. The
// score uses the OLDEST admissible age, which is the conservative end: an
// opportunity that might already be stale is not scored as though it were hours
// old. The basis line prints the whole range, so the number is never presented
// as more precise than the evidence behind it.
func freshnessScore(in input) (int, string) {
	f := in.freshness
	now := in.now

	candidates := make([]freshCandidate, 0, 4)
	for _, c := range []struct {
		label string
		iv    domain.ObservationInterval
	}{
		{"scope changed", f.ScopeChange},
		{"requirements changed", f.RequirementChange},
		{"metadata changed", f.MetadataChange},
		{"lifecycle changed", f.LifecycleChange},
	} {
		if !c.iv.Known() {
			continue
		}
		candidates = append(candidates, freshCandidate{
			label:    c.label,
			age:      c.iv.OldestAge(now),
			interval: c.iv,
		})
	}
	if f.FirstSeenAge > 0 {
		candidates = append(candidates, freshCandidate{label: "first seen", age: f.FirstSeenAge})
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
		return 100, best.label + " " + best.basis(now)
	}
	over := float64(best.age-window) / float64(10*window)
	score := 100 - int(over*100)
	if score < 0 {
		score = 0
	}
	return score, best.label + " " + best.basis(now)
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

// accessDeltaScore scores typed, directional changes to the four access gates.
// Fifty is neutral; each net gate movement changes the score by 25 points, with
// the result clamped to [0,100]. Only explicit change kinds count. Unknown or
// prose-only movements remain neutral rather than being interpreted.
func accessDeltaScore(in input) (int, string) {
	kinds := accessDeltas(in)
	if len(kinds) == 0 {
		return 50, "no typed access-gate delta in bounded evidence"
	}

	gateMovement := map[string]int{}
	for _, raw := range kinds {
		gate, direction := accessGateDirection(domain.ChangeKind(raw))
		if gate != "" {
			gateMovement[gate] += direction
		}
	}
	net := 0
	for _, movement := range gateMovement {
		switch {
		case movement > 0:
			net++
		case movement < 0:
			net--
		}
	}
	score := 50 + 25*net
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, "typed deltas: " + strings.Join(kinds, ", ")
}

// accessDeltas chooses current bounded typed gate changes when present;
// otherwise it reads the latest age-open opportunity window. It returns atomic
// change kinds only, including degraded changes without making them alertable.
func accessDeltas(in input) []string {
	if kinds := currentAccessChangeKinds(in); len(kinds) > 0 {
		return kinds
	}
	window, ok := latestOpportunityWindow(in)
	if !ok {
		return nil
	}
	var kinds []string
	for _, delta := range window.Deltas {
		if gate, direction := accessGateDirection(delta.Kind); gate != "" &&
			matchesAccessDirection(direction, delta.Direction) {
			kinds = append(kinds, string(delta.Kind))
		}
	}
	return sortedUnique(kinds)
}

func currentAccessChangeKinds(in input) []string {
	var kinds []string
	maxAge := in.profile.ChangeWindowMaxAge()
	for _, change := range in.changes {
		gate, direction := accessGateDirection(change.Kind)
		if gate == "" || !matchesAccessDirection(direction, change.Direction) {
			continue
		}
		interval, ok := domain.ChangeInterval(change.Kind, in.freshness)
		if !ok || !interval.PossiblyWithin(in.now, in.profile.ChangeWindowFor(change.Kind)) {
			continue
		}
		if maxAge > 0 && interval.OldestAge(in.now) > maxAge {
			continue
		}
		kinds = append(kinds, string(change.Kind))
	}
	return sortedUnique(kinds)
}

// accessGateDirection maps only explicit directional event kinds onto a gate
// and sign. No prose or before/after string is parsed.
func accessGateDirection(kind domain.ChangeKind) (string, int) {
	switch kind {
	case domain.ChangeReputationLowered:
		return "reputation", 1
	case domain.ChangeReputationRaised:
		return "reputation", -1
	case domain.ChangeKYCRemoved:
		return "kyc", 1
	case domain.ChangeKYCRequired:
		return "kyc", -1
	case domain.ChangeFeeReduced, domain.ChangeFeeRemoved:
		return "submission_fee", 1
	case domain.ChangeFeeIncreased, domain.ChangeFeeIntroduced:
		return "submission_fee", -1
	case domain.ChangePOCRemoved:
		return "proof_of_concept", 1
	case domain.ChangePOCRequired:
		return "proof_of_concept", -1
	default:
		return "", 0
	}
}

func matchesAccessDirection(sign int, direction domain.Direction) bool {
	if sign > 0 {
		return direction == domain.DirectionImproved
	}
	return sign < 0 && direction == domain.DirectionDegraded
}

func currentOpportunityChanges(in input) domain.ChangeSet {
	out := make(domain.ChangeSet, 0, len(in.changes))
	maxAge := in.profile.ChangeWindowMaxAge()
	for _, change := range in.changes {
		if !change.Alertable() {
			continue
		}
		interval, ok := domain.ChangeInterval(change.Kind, in.freshness)
		if !ok || !interval.PossiblyWithin(in.now, in.profile.ChangeWindowFor(change.Kind)) {
			continue
		}
		if maxAge > 0 && interval.OldestAge(in.now) > maxAge {
			continue
		}
		out = append(out, change)
	}
	return out
}

// latestOpportunityWindow returns the newest unexpired window. Crowding is not
// used to hide the observed count movement from scoring; the movement is a raw
// signal even when a separately configured crowding threshold has been crossed.
func latestOpportunityWindow(in input) (domain.OpportunityWindow, bool) {
	opts := domain.OpportunityWindowOptions{MaxAge: in.profile.ChangeWindowMaxAge()}
	var best domain.OpportunityWindow
	found := false
	for _, window := range in.windows {
		if window.ProgramID != in.program.ID || window.Status(in.now, opts) != domain.WindowOpen {
			continue
		}
		if !found || window.Observed.NotAfter.After(best.Observed.NotAfter) ||
			(window.Observed.NotAfter.Equal(best.Observed.NotAfter) && window.ID < best.ID) {
			best = window
			found = true
		}
	}
	return best, found
}

// postChangeCompetitionScore scores the signed count movement from the latest
// opportunity's opening baseline. A decrease is treated as no more submissions;
// the basis always preserves the signed platform-reported movement.
func postChangeCompetitionScore(in input) (int, string) {
	_, delta := postChangeSubmissionObservation(in)
	if delta == nil {
		return 50, "opening baseline or current count is unknown"
	}
	movement := *delta
	submissions := movement
	if submissions < 0 {
		submissions = 0
	}
	score := competitionScoreFor(submissions, 0)
	return score, fmt.Sprintf("%+d platform-reported submissions since the window baseline", movement)
}

// postChangeSubmissionObservation returns the opening count and signed movement
// for the current transition or, when there is no current transition, the latest
// age-open stored window.
func postChangeSubmissionObservation(in input) (*int, *int) {
	if len(currentOpportunityChanges(in)) > 0 {
		count, known := reportedSubmissions(in.program)
		if !known {
			return nil, nil
		}
		baseline := count
		movement := 0
		return &baseline, &movement
	}

	window, ok := latestOpportunityWindow(in)
	if !ok || window.BaselineSubmissions == nil {
		return nil, nil
	}
	baseline := *window.BaselineSubmissions
	if current, known := reportedSubmissions(in.program); known {
		movement := current - baseline
		return &baseline, &movement
	}
	if window.SubmissionsSinceOpen != nil {
		movement := *window.SubmissionsSinceOpen
		return &baseline, &movement
	}
	return &baseline, nil
}

// reportedSubmissions prefers the listing-level count because it is refreshed
// on every scan, then falls back to a detail-only count.
func reportedSubmissions(program domain.Program) (int, bool) {
	if program.Listing.SubmissionCountKnown {
		return program.Listing.SubmissionCount, true
	}
	if program.SubmittedReportsKnown && program.SubmittedReports != nil {
		return *program.SubmittedReports, true
	}
	return 0, false
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

// competitionScore rewards a low observed submission count.
//
// The observed count is reported as-is. Submission count is a weak proxy for
// competition - it includes duplicates, invalid reports, and reports from
// researchers who left long ago - so the basis line always names the number
// rather than asserting a level of competition.
func competitionScore(in input) (int, string) {
	n, known := reportedSubmissions(in.program)
	if !known {
		// Absence is not evidence of low competition, so an unknown count is
		// treated as neutral rather than favourable.
		return 50, "submission count is not published"
	}
	age, _ := in.program.Age(in.now)
	score := competitionScoreFor(n, age)
	return score, fmt.Sprintf("%d submissions reported by the platform", n)
}

// competitionScoreFor maps a submission count onto a 0-100 score.
//
// A very new program with a handful of submissions is the best case. A long
// running program with thousands is the worst. The curve is logarithmic because
// the difference between zero and ten submissions matters far more than the
// difference between one thousand and one thousand one hundred.
func competitionScoreFor(submissions int, age time.Duration) int {
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
	if age > 0 && age < 24*time.Hour && score < 85 {
		score += 10
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
func rawInputs(in input) domain.TriageInputs {
	p, f, cs := in.program, in.freshness, in.changes
	material := 0
	for _, c := range cs {
		if c.Severity.AtLeast(domain.SeverityMedium) {
			material++
		}
	}
	count, countKnown := reportedSubmissions(p)
	baseline, movement := postChangeSubmissionObservation(in)
	inputs := domain.TriageInputs{
		SubmissionCountKnown:           countKnown,
		AccessDeltas:                   accessDeltas(in),
		PostChangeSubmissionDeltaKnown: movement != nil,
		ProgramAgeBasis:                f.ProgramAgeBasis,
		ScopeChange:                    f.ScopeChange,
		RequirementChange:              f.RequirementChange,
		MetadataChange:                 f.MetadataChange,
		LifecycleChange:                f.LifecycleChange,
		ScopeSize:                      len(p.InScopeTargets()),
		ChangeCount:                    material,
		MaxBountyUSD:                   p.MaxBountyUSD,
	}
	if countKnown {
		v := count
		inputs.SubmittedReports = &v
	}
	if baseline != nil {
		v := *baseline
		inputs.PostChangeBaselineSubmissions = &v
	}
	if movement != nil {
		v := *movement
		inputs.PostChangeSubmissionDelta = &v
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
