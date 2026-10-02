// Package alerts decides when an observation deserves a notification, renders
// it, and fingerprints it so the same condition cannot be announced twice.
//
// Rendering happens here rather than in a notifier, for two reasons: the output
// is fully determined by engine state and can therefore be asserted in tests
// without a mail transport, and delivery stays idempotent because the exact bytes
// to be sent are recorded before the send is attempted.
package alerts

import (
	"sort"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// Generator produces alerts from scan results.
type Generator struct {
	profile *config.Profile
	now     func() time.Time
}

// NewGenerator builds a generator for a profile.
func NewGenerator(profile *config.Profile, now func() time.Time) *Generator {
	if now == nil {
		now = time.Now
	}
	return &Generator{profile: profile, now: now}
}

// PriorDecision is what was known about a program on the previous scan.
//
// It is required because alert selection depends on transitions, not on the
// current state alone: a newly eligible program and a newly discovered program
// are different events with different fingerprints.
type PriorDecision struct {
	// Known reports whether the program was evaluated on a previous scan.
	Known bool
	// Eligible is the previous eligibility verdict.
	Eligible bool
}

// Candidate is one evaluated observation offered for alerting.
type Candidate struct {
	Program  domain.Program
	Diff     domain.Diff
	Decision domain.EligibilityDecision
	Triage   domain.Triage
	Fresh    domain.Freshness
	Prior    PriorDecision
}

// Decide returns the alert to raise for a candidate, or nil if none is due.
//
// The triggers mirror the ones the mandate specifies, and each is separately
// configurable so that a researcher can be told about new programs without being
// told about every metadata edit.
func (g *Generator) Decide(c Candidate) *domain.Alert {
	cfg := g.profile.Notifications
	if !cfg.Enabled {
		return nil
	}

	kind, trigger := g.selectKind(c)
	if kind == "" {
		return nil
	}

	// Severity gate. A low-severity change never alerts, even if a trigger
	// matched, because a notification must be worth interrupting for.
	if !g.severityGate(c, kind) {
		return nil
	}

	// Eligibility gate. When the profile requires it, an ineligible program is
	// silent even if it just appeared. This is the setting that makes the
	// difference between a notification channel and a firehose.
	if cfg.RequireEligible && !c.Decision.Eligible {
		return nil
	}

	now := g.now().UTC()
	alert := domain.Alert{
		Kind:       kind,
		ProgramID:  c.Program.ID,
		Program:    c.Program,
		Changes:    c.Diff.Changes,
		Decision:   c.Decision,
		Triage:     c.Triage,
		Freshness:  c.Fresh,
		DetectedAt: now,
	}
	alert.Fingerprint = domain.ComputeFingerprint(kind, c.Program.ID, c.Diff.Changes, c.Decision, trigger)
	alert.Subject, alert.Body = Render(c, g.profile)
	return &alert
}

// selectKind picks the single most significant trigger for a candidate.
//
// Only one alert is raised per program per scan. A new program that is also a
// scope expansion is reported as a new program, because that is the stronger
// claim, and reporting both would double the noise for one event.
func (g *Generator) selectKind(c Candidate) (domain.AlertKind, string) {
	cfg := g.profile.Notifications

	// A program the profile previously rejected and now accepts is the highest
	// value signal: it means an opportunity opened without anyone announcing it.
	if cfg.AlertOnNewlyEligible && c.Prior.Known && !c.Prior.Eligible && c.Decision.Eligible {
		return domain.AlertNewlyEligible, "newly_eligible"
	}

	if c.Diff.IsNew {
		if cfg.AlertOnNewPrograms {
			return domain.AlertNewQualifying, "new_program"
		}
		return "", ""
	}

	// Previously rejected and still rejected: nothing to say even if it changed,
	// because the change did not make it reachable.
	if c.Prior.Known && !c.Prior.Eligible && !c.Decision.Eligible {
		return "", ""
	}

	// Reactivation outranks other changes: a reopened program is a fresh window.
	if c.Diff.Changes.Contains(domain.ChangeProgramReactivated) {
		if cfg.AlertOnMaterialChange {
			return domain.AlertMaterialChange, "reactivated"
		}
		return "", ""
	}

	if cfg.AlertOnScopeExpansion && hasSurfaceExpansion(c) {
		return domain.AlertScopeExpansion, "scope_expansion"
	}

	if cfg.AlertOnMaterialChange && c.Diff.Material() {
		return domain.AlertMaterialChange, "material_change"
	}
	return "", ""
}

// hasSurfaceExpansion reports whether the change set added attack surface.
//
// Additions count; removals do not. Losing scope is a change but not an opening.
func hasSurfaceExpansion(c Candidate) bool {
	for _, ch := range c.Diff.Changes {
		switch ch.Kind {
		case domain.ChangeTargetAdded, domain.ChangeAPIAdded,
			domain.ChangeRepositoryAdded, domain.ChangeMobileAdded,
			domain.ChangeSurfaceChanged:
			// A surface change that removes more than it adds is not an
			// expansion, so the counts are compared before reporting.
			if countKinds(c.Diff.Changes, domain.ChangeTargetAdded, domain.ChangeAPIAdded,
				domain.ChangeRepositoryAdded, domain.ChangeMobileAdded) >
				countKinds(c.Diff.Changes, domain.ChangeTargetRemoved, domain.ChangeAPIRemoved,
					domain.ChangeRepositoryRemoved) {
				return true
			}
		}
	}
	return false
}

func countKinds(cs domain.ChangeSet, kinds ...domain.ChangeKind) int {
	n := 0
	for _, c := range cs {
		for _, k := range kinds {
			if c.Kind == k {
				n++
				break
			}
		}
	}
	return n
}

// severityGate verifies the change set clears the configured severity floor.
//
// A newly discovered program is exempt from the floor because discovering it is
// itself the highest-severity event there is, regardless of any change set.
func (g *Generator) severityGate(c Candidate, kind domain.AlertKind) bool {
	if kind == domain.AlertNewQualifying {
		return true
	}
	floor := g.profile.MinSeverity()
	for _, ch := range c.Diff.Changes {
		if ch.Severity.AtLeast(floor) {
			return true
		}
	}
	return false
}

// SortByPriority orders alerts most important first, breaking ties
// deterministically so that a batch send is stable.
func SortByPriority(in []domain.Alert) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Triage.Total != in[j].Triage.Total {
			return in[i].Triage.Total > in[j].Triage.Total
		}
		hi := severityRank(in[i].Changes.Highest())
		hj := severityRank(in[j].Changes.Highest())
		if hi != hj {
			return hi > hj
		}
		// The fingerprint is a stable final tiebreaker.
		return in[i].Fingerprint < in[j].Fingerprint
	})
}

func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	default:
		return 1
	}
}

// cap applies the per-scan alert limit, reporting how many were dropped so the
// summary can say so rather than silently truncating.
func (g *Generator) cap(alerts []domain.Alert) ([]domain.Alert, int) {
	limit := g.profile.Notifications.MaxPerScan
	if limit <= 0 || len(alerts) <= limit {
		return alerts, 0
	}
	SortByPriority(alerts)
	return alerts[:limit], len(alerts) - limit
}

// CapAlerts applies the configured per-scan limit, reporting how many were
// dropped so a caller can state that rather than silently truncating.
func (g *Generator) CapAlerts(alerts []domain.Alert) ([]domain.Alert, int) {
	return g.cap(alerts)
}
