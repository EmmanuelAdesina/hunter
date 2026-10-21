package verify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Evidence is the factual bundle a reader is given.
//
// The bundle is a flat set of named facts. The names are the citation
// vocabulary: a statement in the delivered message is checkable only if the
// message says which fact it came from, and that check is only meaningful if
// the set of citable facts is fixed and known.
type Evidence struct {
	// Program identifies what is being talked about.
	Program EvidenceProgram `json:"program"`

	// ClaimedChange is what the pipeline says happened.
	ClaimedChange EvidenceChange `json:"claimed_change"`

	// Facts are the citable facts, keyed by name.
	Facts map[string]string `json:"facts"`

	// Eligibility are the reasons the program passed the profile's gates.
	Eligibility []string `json:"eligibility"`
}

// EvidenceProgram identifies the program.
type EvidenceProgram struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// EvidenceChange is the claimed change, stated in the pipeline's own words.
type EvidenceChange struct {
	Kind   string `json:"kind"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
	Detail string `json:"detail"`
	Window string `json:"window"`
}

// Fact returns the value of a citable fact.
func (e Evidence) Fact(key string) (string, bool) {
	v, ok := e.Facts[key]
	return v, ok
}

// buildEvidence assembles the bundle for one request.
//
// Every fact is a value that was observed, never a conclusion. The reader
// draws the conclusions; this function only reports what was seen.
func buildEvidence(req Request) Evidence {
	p := req.Program
	ev := Evidence{
		Program: EvidenceProgram{
			ID:     p.ID,
			Name:   p.Name,
			URL:    p.URL,
			Source: p.Source,
		},
		Facts:       map[string]string{},
		Eligibility: req.Decision.Reasons,
	}

	set := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		ev.Facts[key] = value
	}

	set("program.id", p.ID)
	set("program.name", p.Name)
	set("program.url", p.URL)
	set("program.source", p.Source)

	// The source's own vocabulary, verbatim.
	set("live.status", p.RawStatus)
	set("live.state", p.RawState)
	set("live.activity_status", p.ActivityStatus)
	if p.EndsAt != nil {
		set("live.end_date", p.EndsAt.UTC().Format(time.DateOnly))
	}
	if p.StartedAt != nil {
		set("live.start_date", p.StartedAt.UTC().Format(time.DateOnly))
	}
	if p.IsUnending {
		set("live.is_unending", "true")
	}
	set("live.normalized_state", string(p.State))

	// The page a researcher would open.
	for k, v := range p.PageMarkers {
		set("page."+k, v)
	}

	// The listing row, which is what a sweep sees cheaply.
	set("listing.activity_status", p.Listing.ActivityStatus)
	set("listing.status", p.Listing.Status)
	set("listing.state", p.Listing.State)
	set("listing.reward", p.Listing.RewardRaw)
	set("listing.rewards_paid", p.Listing.RewardsPaidRaw)

	// The access gates, as the platform states them.
	set("gate.reputation", describeReputation(p.Reputation))
	set("gate.kyc", p.KYC.String())
	set("gate.poc", p.POC.String())
	set("gate.submission_fee", describeFee(p.Fee))
	if p.MaxBountyUSD != nil {
		set("gate.bounty_ceiling_usd", fmt.Sprintf("%.0f", *p.MaxBountyUSD))
	}
	if p.MinBountyUSD != nil {
		set("gate.bounty_floor_usd", fmt.Sprintf("%.0f", *p.MinBountyUSD))
	}
	if p.SubmittedReportsKnown && p.SubmittedReports != nil {
		set("competition.submissions", fmt.Sprintf("%d", *p.SubmittedReports))
	}
	if p.RewardsPaidUSD != nil {
		set("competition.paid_out_usd", fmt.Sprintf("%.2f", *p.RewardsPaidUSD))
	}
	for _, t := range p.Targets {
		if t.InScope {
			set("scope.target."+string(t.Kind), t.Identifier)
		}
	}

	// The claimed change itself.
	if len(req.Changes) > 0 {
		c := req.Changes[0]
		ev.ClaimedChange = EvidenceChange{
			Kind:   string(c.Kind),
			Field:  c.Field,
			Before: c.Before,
			After:  c.After,
			Detail: c.Detail,
		}
		set("change.kind", string(c.Kind))
		set("change.field", c.Field)
		set("change.before", c.Before)
		set("change.after", c.After)
		set("change.detail", c.Detail)
		set("change.severity", string(c.Severity))
	}

	// The observation window that bounds the change.
	for _, w := range []struct {
		key   string
		iv    domain.ObservationInterval
		label string
	}{
		{"change.window.scope", req.Fresh.ScopeChange, "scope"},
		{"change.window.requirements", req.Fresh.RequirementChange, "requirements"},
		{"change.window.metadata", req.Fresh.MetadataChange, "metadata"},
		{"change.window.lifecycle", req.Fresh.LifecycleChange, "lifecycle"},
	} {
		if w.iv.Known() {
			set(w.key, w.iv.Humanize(req.Now))
		}
	}

	return ev
}

func describeReputation(g domain.ReputationGate) string {
	switch {
	case !g.Known():
		return "unknown"
	case g.Present == domain.TriNo:
		return "none required"
	default:
		return fmt.Sprintf("%d reputation points", g.Points)
	}
}

func describeFee(f domain.FeeGate) string {
	switch {
	case !f.Known():
		return "unknown"
	case f.Present == domain.TriNo:
		return "none"
	default:
		return fmt.Sprintf("%.2f USD", f.USD)
	}
}

// renderEvidence serializes the bundle for the model.
//
// It is sent as JSON so that the reader sees the same names the record keeps,
// and so that a returned citation can be checked against it mechanically.
func renderEvidence(ev Evidence) (string, error) {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return "", fmt.Errorf("render evidence: %w", err)
	}
	return string(b), nil
}
