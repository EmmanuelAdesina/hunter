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
	Program domain.Program

	// LaunchAge is how long ago the source reported the program launching, and
	// LaunchKnown whether it reported one. Both are populated by the generator
	// before rendering, so the subject line and the message body cannot quote
	// different numbers for the same program.
	LaunchAge   time.Duration
	LaunchKnown bool
	Diff        domain.Diff
	Decision    domain.EligibilityDecision
	Triage      domain.Triage
	Fresh       domain.Freshness
	Prior       PriorDecision
}

// Decide returns the alert to raise for a candidate, or nil if none is due.
//
// Each trigger is gated by its OWN recency window, measured from the evidence for
// that trigger rather than from the program's age. A newly launched program is
// recent by its launch date; a scope expansion is recent by the interval in which
// the scope was observed to change. Those are different clocks and conflating
// them is what previously made a five-year-old program with a brand-new API
// unreportable: the launch-age gate ran first and suppressed everything behind it.
//
// A trigger whose evidence cannot be bounded raises nothing. "This changed at
// some point we cannot place" is not evidence of freshness, and treating it as
// such would re-admit every program whose launch date the source omits.
func (g *Generator) Decide(c Candidate) *domain.Alert {
	cfg := g.profile.Notifications
	if !cfg.Enabled {
		return nil
	}

	now := g.now().UTC()
	launchAge, launchKnown := launchAge(c.Program, now)

	kind, trigger := g.selectKind(c, launchAge, launchKnown, now)
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

	alert := domain.Alert{
		Kind:        kind,
		ProgramID:   c.Program.ID,
		Program:     c.Program,
		Changes:     c.Diff.Changes,
		Decision:    c.Decision,
		Triage:      c.Triage,
		Freshness:   c.Fresh,
		DetectedAt:  now,
		LaunchAge:   launchAge,
		LaunchKnown: launchKnown,
	}
	// A change alert's identity includes the transition it came from, not just the
	// change content.
	//
	// Without it, a program that adds an API, loses it, and adds it again produces
	// two byte-identical change sets and therefore one fingerprint - so the second
	// opportunity, which is a genuinely new opening that other researchers have
	// not seen, would be suppressed as a duplicate. The interval's lower bound is
	// the observation that preceded the change, so it identifies the transition
	// exactly while staying identical across scans that observe the same one.
	alert.Fingerprint = domain.ComputeFingerprint(kind, c.Program.ID, c.Diff.Changes, c.Decision,
		trigger, evidenceKey(c, kind, now))

	alert.Subject, alert.Body, alert.HTMLBody = Render(c, g.profile, now)
	return &alert
}

// launchAge returns how long ago the source says the program launched, and
// whether it said so at all.
//
// A program with no published launch date returns ok=false. That is the
// system's central rule applied to recency: "recently launched" cannot be
// established, so no alert is raised. Treating an unknown launch date as recent
// would put every program the source is vague about straight back on the channel.
func launchAge(p domain.Program, now time.Time) (time.Duration, bool) {
	if p.StartedAt == nil || p.StartedAt.IsZero() {
		return 0, false
	}
	age := now.Sub(*p.StartedAt)
	if age < 0 {
		// A future launch date is clock skew or a typo, and is not evidence of
		// a freshly launched program.
		return 0, false
	}
	return age, true
}

// withinLaunchWindow reports whether a launch age falls inside the window.
func withinLaunchWindow(age time.Duration, known bool, window time.Duration) bool {
	return known && age <= window
}

// stateAllowsAlert reports whether the program's current lifecycle state is one
// the profile considers alert-worthy. An unconfigured list allows everything,
// preserving the behavior of profiles written before the setting existed.
func (g *Generator) stateAllowsAlert(state domain.ProgramState) bool {
	listed := g.profile.AlertOnStates()
	if len(listed) == 0 {
		return true
	}
	for _, s := range listed {
		if s == state {
			return true
		}
	}
	return false
}

// selectKind picks the single most significant trigger for a candidate.
//
// Each branch carries its own recency evidence. The launch window governs only
// the two triggers that are genuinely about a program's age; the change triggers
// are governed by the interval in which the change was observed to happen. One
// alert is raised per program per scan, and the strongest claim wins, so a
// program that is both newly launched and newly eligible is reported once.
func (g *Generator) selectKind(c Candidate, launchAge time.Duration, launchKnown bool, now time.Time) (domain.AlertKind, string) {
	cfg := g.profile.Notifications
	launchWindow := g.profile.NewProgramWindow()

	// program_states.alert_on_state lists the lifecycle states that warrant an
	// alert in their own right. When configured, every alert kind requires the
	// program to currently be in a listed state; when empty, no state gating
	// applies. This is what separates "evaluate and track" (allowed states)
	// from "page the researcher" (alert states): a profile may watch paused
	// programs without being woken for them.
	if !g.stateAllowsAlert(c.Program.State) {
		return "", ""
	}

	// A program seen for the first time is the primary event.
	if c.Diff.IsNew {
		if cfg.AlertOnNewPrograms && withinLaunchWindow(launchAge, launchKnown, launchWindow) {
			return domain.AlertNewQualifying, "new_program"
		}
		// The program is new to the catalogue but not to the world. A new program
		// whose launch date the source does not publish is still an opportunity,
		// just not one that can be shown to be recent; it falls through to the
		// change triggers below, which have their own evidence.
	}

	// A program that was seen but could not be assessed, and can now, is still
	// worth reporting. The launch window still applies: "newly eligible" is most
	// actionable when the program is also new.
	if cfg.AlertOnNewlyEligible && c.Prior.Known && !c.Prior.Eligible && c.Decision.Eligible &&
		withinLaunchWindow(launchAge, launchKnown, launchWindow) {
		return domain.AlertNewlyEligible, "newly_eligible"
	}

	// The remaining triggers concern programs that already existed. They are
	// gated on the recency of the CHANGE, established from the interval in which
	// the change was observed, not on how old the program is.
	if cfg.AlertOnScopeExpansion && g.changeWithinWindow(c, domain.AlertScopeExpansion, now) &&
		hasSurfaceExpansion(c) {
		return domain.AlertScopeExpansion, "scope_expansion"
	}
	if cfg.AlertOnMaterialChange && g.changeWithinWindow(c, domain.AlertMaterialChange, now) &&
		c.Diff.Changes.AlertableMaterial() {
		return domain.AlertMaterialChange, "material_change"
	}
	return "", ""
}

// evidenceKey returns a deterministic discriminator for a change-triggered alert.
//
// It is empty for launch-triggered alerts, which are already identified by program
// and kind. For a change it is the lower bound of the interval that bounds the
// change, which distinguishes two separate transitions that happen to produce
// identical change content.
func evidenceKey(c Candidate, kind domain.AlertKind, now time.Time) string {
	if kind != domain.AlertScopeExpansion && kind != domain.AlertMaterialChange {
		return ""
	}
	var best domain.ObservationInterval
	for _, ch := range c.Diff.Changes {
		if !ch.Alertable() {
			continue
		}
		iv, ok := changeInterval(c.Fresh, ch.Kind)
		if !ok {
			continue
		}
		// The earliest bounding observation identifies the transition as a whole.
		if !best.Known() || iv.NotBefore.Before(best.NotBefore) {
			best = iv
		}
	}
	if !best.Known() {
		return ""
	}
	return best.NotBefore.UTC().Format(time.RFC3339)
}

// changeWithinWindow reports whether the program's changes are recent enough to
// alert on.
//
// The evidence is whichever fingerprint group actually moved, because a scope
// expansion and a requirement relaxation are different events with different
// intervals, and each must be judged against the window configured for it. The
// gate is permissive at the boundary: a change that may still be inside the
// window alerts, and the rendered age range discloses the ambiguity.
//
// A change with no bounded interval never alerts. This is the single most
// important rule in the trigger, and it is the mirror image of the launch rule:
// "recently changed" cannot be established, so nothing is claimed.
func (g *Generator) changeWithinWindow(c Candidate, kind domain.AlertKind, now time.Time) bool {
	for _, ch := range c.Diff.Changes {
		if !ch.Alertable() {
			continue
		}
		iv, ok := changeInterval(c.Fresh, ch.Kind)
		if !ok {
			continue
		}
		window := g.profile.ChangeWindowFor(ch.Kind)
		if iv.PossiblyWithin(now, window) {
			return true
		}
	}
	return false
}

// changeInterval returns the observation interval that bounds a change of the
// given kind.
func changeInterval(f domain.Freshness, kind domain.ChangeKind) (domain.ObservationInterval, bool) {
	return domain.ChangeInterval(kind, f)
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

// selectedTrigger returns the trigger the generator would choose for rendering.
func selectedTrigger(c Candidate, profile *config.Profile, now time.Time) domain.AlertKind {
	age, known := launchAge(c.Program, now)
	generator := NewGenerator(profile, func() time.Time { return now })
	kind, _ := generator.selectKind(c, age, known, now)
	return kind
}

// hasSurfaceExpansion reports whether the change set added attack surface.
//
// Additions count; removals do not. Losing scope is a change but not an opening.
func hasSurfaceExpansion(c Candidate) bool {
	for _, change := range c.Diff.Changes {
		if isSurfaceExpansion(change) {
			return true
		}
	}
	return false
}

// isSurfaceExpansion reports whether one alertable change actually added
// testable surface. Other improvements (for example, a removed KYC gate) are
// material changes, but they are not scope expansions.
func isSurfaceExpansion(change domain.Change) bool {
	if !change.Alertable() || !change.Severity.AtLeast(domain.SeverityMedium) {
		return false
	}
	switch change.Kind {
	case domain.ChangeTargetAdded, domain.ChangeAPIAdded,
		domain.ChangeRepositoryAdded, domain.ChangeMobileAdded,
		domain.ChangeTargetInScope,
		domain.ChangeScopeChanged, domain.ChangeSurfaceChanged:
		return true
	default:
		return false
	}
}
