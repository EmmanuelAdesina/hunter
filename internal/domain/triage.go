package domain

import (
	"sort"
	"time"
)

// Triage is a deterministic attention-prioritisation result.
//
// This is explicitly not a prediction of vulnerability likelihood. It is a
// transparent ordering heuristic whose components are published individually so
// that the researcher can see and disagree with every input. Nothing here is
// learned, sampled, or model-generated, and no component claims to estimate
// exploitability.
type Triage struct {
	// Total is the weighted sum of the components below, clamped to [0,100].
	Total int `json:"total"`

	// Components holds every individual signal and its own 0-100 value.
	Components []TriageComponent `json:"components"`

	// Inputs records the raw facts the components were derived from, so that a
	// score can always be traced back to observed data.
	Inputs TriageInputs `json:"inputs"`
}

// TriageComponent is one named contribution to the total.
type TriageComponent struct {
	Name  string `json:"name"`
	Value int    `json:"value"`

	// Weight is the share of the total this component can contribute.
	Weight float64 `json:"weight"`

	// Basis explains the value in one line.
	Basis string `json:"basis,omitempty"`
}

// TriageInputs holds the raw, untransformed signals behind a triage score.
//
// These are the numbers the mandate requires to stay visible. A score is only
// trustworthy when its inputs are inspectable, and a competition signal in
// particular must never be presented as more than what was observed.
type TriageInputs struct {
	// SubmittedReports is the source's public submission count.
	SubmittedReports *int `json:"submitted_reports,omitempty"`

	// SubmissionCountKnown distinguishes a real zero from an absent count.
	SubmissionCountKnown bool `json:"submission_count_known"`

	// AccessDeltas lists the typed, directional gate movements used by the
	// access-delta component. It contains change kinds, not an editorial summary.
	AccessDeltas []string `json:"access_deltas,omitempty"`

	// PostChangeBaselineSubmissions is the platform-reported count observed when
	// the latest opportunity window opened.
	PostChangeBaselineSubmissions *int `json:"post_change_baseline_submissions,omitempty"`

	// PostChangeSubmissionDelta is the signed platform-reported count movement
	// from the baseline captured when the latest opportunity window opened.
	PostChangeSubmissionDelta *int `json:"post_change_submission_delta,omitempty"`

	// PostChangeSubmissionDeltaKnown distinguishes an unknown baseline/count from
	// an observed zero movement.
	PostChangeSubmissionDeltaKnown bool `json:"post_change_submission_delta_known"`

	// ProgramAge and its basis.
	ProgramAge      time.Duration `json:"program_age,omitempty"`
	ProgramAgeBasis AgeBasis      `json:"program_age_basis,omitempty"`

	// ScopeChange and RequirementChange bound when those fingerprint groups last
	// moved. They are stored as intervals rather than durations so that a score
	// can never be traced back to a change time the system did not observe.
	ScopeChange       ObservationInterval `json:"scope_change"`
	RequirementChange ObservationInterval `json:"requirement_change"`
	MetadataChange    ObservationInterval `json:"metadata_change"`
	LifecycleChange   ObservationInterval `json:"lifecycle_change"`

	// ScopeSize is the number of in-scope assets.
	ScopeSize int `json:"scope_size"`

	// ChangeCount is the number of material changes detected.
	ChangeCount int `json:"change_count"`

	// MaxBountyUSD is the largest stated bounty.
	MaxBountyUSD *float64 `json:"max_bounty_usd,omitempty"`
}

// Component returns a component by name.
func (t Triage) Component(name string) (TriageComponent, bool) {
	for _, c := range t.Components {
		if c.Name == name {
			return c, true
		}
	}
	return TriageComponent{}, false
}

// Values renders the components as a stable, human-readable block.
//
// Output ordering is fixed by the caller-supplied weights rather than by map
// iteration, so two runs over the same program render identically.
func (t Triage) Values() []string {
	out := make([]string, 0, len(t.Components))
	for _, c := range t.Components {
		line := c.Name + ": " + itoa(c.Value)
		if c.Basis != "" {
			line += "  (" + c.Basis + ")"
		}
		out = append(out, line)
	}
	return out
}

// sortComponents orders components by name so rendering is stable.
func sortComponents(cs []TriageComponent) {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
}

// itoa avoids a strconv import in the presentation path while keeping the
// conversion in one place.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// SortComponents orders triage components by name so that rendering is stable
// between runs.
func SortComponents(cs []TriageComponent) { sortComponents(cs) }
