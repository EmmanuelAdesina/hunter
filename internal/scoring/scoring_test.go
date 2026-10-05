package scoring

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

const scoringProfile = `
profile:
  name: scoring-test
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
  target_domains:
    included: [api, web_application]
  notifications:
    alert_on_new_programs: true
    new_program_window: 24h
    change_windows:
      default: 72h
      access_improved: 72h
`

func mustScoringProfile(t *testing.T) *config.Profile {
	t.Helper()
	profile, err := config.Parse([]byte(scoringProfile))
	if err != nil {
		t.Fatalf("parse scoring profile: %v", err)
	}
	return profile
}

func TestComponentWeightsRetainOneScore(t *testing.T) {
	total := 0.0
	seen := map[string]bool{}
	for _, component := range components {
		if seen[component.name] {
			t.Errorf("duplicate component %q", component.name)
		}
		seen[component.name] = true
		total += component.weight
	}
	if math.Abs(total-1) > 1e-9 {
		t.Errorf("component weights sum to %.12f, want 1", total)
	}
	for _, name := range []string{"access delta", "post-change competition"} {
		if !seen[name] {
			t.Errorf("component table is missing %q", name)
		}
	}
}

func TestAccessDeltaAndPostChangeCompetitionUseWindowEvidence(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	profile := mustScoringProfile(t)
	baseline, current := 5, 8
	program := domain.Program{
		ID: "hackenproof:alpha",
		Listing: domain.ListingSignal{
			SubmissionCount:      current,
			SubmissionCountKnown: true,
		},
		Targets: domain.Targets{{Kind: domain.KindAPI, Identifier: "api.example.test", InScope: true}},
	}
	fresh := domain.Freshness{
		RequirementChange: domain.NewObservationInterval(now.Add(-11*time.Minute), now.Add(-9*time.Minute)),
	}
	change := domain.Change{
		Kind: domain.ChangeKYCRemoved, Severity: domain.SeverityMedium,
		Direction: domain.DirectionImproved, Field: "kyc",
	}
	scorer := New(profile, func() time.Time { return now })

	opened := scorer.ScoreWithWindows(program, domain.EligibilityDecision{}, fresh,
		domain.ChangeSet{change}, nil)
	access, ok := opened.Component("access delta")
	if !ok || access.Value != 75 || !strings.Contains(access.Basis, "KYC_REMOVED") {
		t.Errorf("opening access-delta component = %+v, present=%t", access, ok)
	}
	post, ok := opened.Component("post-change competition")
	if !ok || post.Value != 100 || !strings.Contains(post.Basis, "+0") {
		t.Errorf("opening post-change component = %+v, present=%t", post, ok)
	}
	if opened.Inputs.PostChangeBaselineSubmissions == nil ||
		*opened.Inputs.PostChangeBaselineSubmissions != current ||
		opened.Inputs.PostChangeSubmissionDelta == nil ||
		*opened.Inputs.PostChangeSubmissionDelta != 0 {
		t.Errorf("opening raw count evidence = %+v", opened.Inputs)
	}

	observed := domain.NewObservationInterval(now.Add(-11*time.Minute), now.Add(-9*time.Minute))
	window := domain.NewOpportunityWindow(program.ID, "Alpha", observed, domain.Deltas{{
		Kind: domain.ChangeKYCRemoved, Field: "kyc", Direction: domain.DirectionImproved,
	}}, domain.OpportunityWindowOptions{})
	window.SetOpeningSubmissions(&baseline, true)
	window.Observe(&current, true)

	later := scorer.ScoreWithWindows(program, domain.EligibilityDecision{}, fresh, nil,
		[]domain.OpportunityWindow{window})
	access, ok = later.Component("access delta")
	if !ok || access.Value != 75 || !strings.Contains(access.Basis, "KYC_REMOVED") {
		t.Errorf("stored access-delta component = %+v, present=%t", access, ok)
	}
	post, ok = later.Component("post-change competition")
	if !ok || post.Value <= 50 || !strings.Contains(post.Basis, "+3") {
		t.Errorf("stored post-change component = %+v, present=%t", post, ok)
	}
	if later.Inputs.PostChangeBaselineSubmissions == nil ||
		*later.Inputs.PostChangeBaselineSubmissions != baseline ||
		later.Inputs.PostChangeSubmissionDelta == nil ||
		*later.Inputs.PostChangeSubmissionDelta != current-baseline {
		t.Errorf("stored raw count evidence = %+v", later.Inputs)
	}
	if len(later.Inputs.AccessDeltas) != 1 || later.Inputs.AccessDeltas[0] != string(domain.ChangeKYCRemoved) {
		t.Errorf("access delta inputs = %v, want the atomic KYC_REMOVED kind", later.Inputs.AccessDeltas)
	}
}

func TestDegradedAccessDeltaLowersComponentWithoutOpeningWindow(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	profile := mustScoringProfile(t)
	fresh := domain.Freshness{
		RequirementChange: domain.NewObservationInterval(now.Add(-11*time.Minute), now.Add(-9*time.Minute)),
	}
	change := domain.Change{
		Kind: domain.ChangeKYCRequired, Severity: domain.SeverityMedium,
		Direction: domain.DirectionDegraded, Field: "kyc",
	}

	triage := New(profile, func() time.Time { return now }).ScoreWithWindows(
		domain.Program{ID: "hackenproof:alpha"}, domain.EligibilityDecision{}, fresh,
		domain.ChangeSet{change}, nil,
	)
	component, ok := triage.Component("access delta")
	if !ok || component.Value != 25 || !strings.Contains(component.Basis, "KYC_REQUIRED") {
		t.Errorf("degraded access component = %+v, present=%t", component, ok)
	}
	if len(triage.Inputs.AccessDeltas) != 1 || triage.Inputs.AccessDeltas[0] != string(domain.ChangeKYCRequired) {
		t.Errorf("degraded access inputs = %v", triage.Inputs.AccessDeltas)
	}
}

func TestPostChangeCompetitionDoesNotInventUnknownOpeningBaseline(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	profile := mustScoringProfile(t)
	current := 8
	program := domain.Program{
		ID: "hackenproof:alpha",
		Listing: domain.ListingSignal{
			SubmissionCount:      current,
			SubmissionCountKnown: true,
		},
	}
	window := domain.NewOpportunityWindow(program.ID, "Alpha",
		domain.NewObservationInterval(now.Add(-time.Hour), now.Add(-50*time.Minute)),
		domain.Deltas{{Kind: domain.ChangeKYCRemoved, Direction: domain.DirectionImproved}},
		domain.OpportunityWindowOptions{})
	window.Observe(&current, true)

	triage := New(profile, func() time.Time { return now }).ScoreWithWindows(
		program, domain.EligibilityDecision{}, domain.Freshness{}, nil,
		[]domain.OpportunityWindow{window},
	)
	component, ok := triage.Component("post-change competition")
	if !ok || component.Value != 50 || !strings.Contains(component.Basis, "baseline or current count is unknown") {
		t.Errorf("unknown-baseline component = %+v, present=%t", component, ok)
	}
	if triage.Inputs.PostChangeBaselineSubmissions != nil ||
		triage.Inputs.PostChangeSubmissionDelta != nil ||
		triage.Inputs.PostChangeSubmissionDeltaKnown {
		t.Errorf("unknown opening baseline was inferred: %+v", triage.Inputs)
	}
}

func TestPostChangeCompetitionPreservesNegativeMovement(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	profile := mustScoringProfile(t)
	baseline, current := 12, 8
	program := domain.Program{
		ID: "hackenproof:alpha",
		Listing: domain.ListingSignal{
			SubmissionCount:      current,
			SubmissionCountKnown: true,
		},
	}
	window := domain.NewOpportunityWindow(program.ID, "Alpha",
		domain.NewObservationInterval(now.Add(-time.Hour), now.Add(-50*time.Minute)),
		domain.Deltas{{Kind: domain.ChangeKYCRemoved, Direction: domain.DirectionImproved}},
		domain.OpportunityWindowOptions{})
	window.SetOpeningSubmissions(&baseline, true)
	window.Observe(&current, true)

	triage := New(profile, func() time.Time { return now }).ScoreWithWindows(
		program, domain.EligibilityDecision{}, domain.Freshness{}, nil,
		[]domain.OpportunityWindow{window},
	)
	component, ok := triage.Component("post-change competition")
	if !ok || component.Value != 100 || !strings.Contains(component.Basis, "-4") {
		t.Errorf("post-change component = %+v, present=%t", component, ok)
	}
	if triage.Inputs.PostChangeSubmissionDelta == nil || *triage.Inputs.PostChangeSubmissionDelta != -4 {
		t.Errorf("signed count movement = %+v, want -4", triage.Inputs.PostChangeSubmissionDelta)
	}
}
