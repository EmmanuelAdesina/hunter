// Package diff detects semantic change between two observations of a program.
//
// Detection is content-based, not timestamp-based. The source's own update
// marker has day resolution and, more importantly, a program can change without
// the marker moving at all. Every comparison here therefore runs over
// fingerprints and explicit field comparisons.
//
// The comparison is total: a change that produces no event is a real conclusion,
// not an absence of checking.
package diff

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Detector compares previous state to a current observation.
type Detector struct {
	// now supplies the current time so that observations are reproducible.
	now func() time.Time
}

// NewDetector builds a detector.
func NewDetector(now func() time.Time) *Detector {
	if now == nil {
		now = time.Now
	}
	return &Detector{now: now}
}

// Compare classifies the difference between a previous record and a current one.
//
// A nil previous means the program has never been observed, which is reported as
// NEW_PROGRAM. Everything else is derived from field-level comparison.
func (d *Detector) Compare(prev, cur domain.Program) domain.Diff {
	now := d.now().UTC()

	out := domain.Diff{
		ProgramID:          cur.ID,
		Changes:            domain.ChangeSet{},
		FirstSeenAt:        now,
		PreviousLastSeenAt: prev.LastSeenAt,
	}

	if prev.ID == "" {
		out.IsNew = true
		out.FirstSeenAt = firstNonZero(cur.FirstSeenAt, now)
		out.Changes = append(out.Changes, domain.Change{
			Kind:     domain.ChangeNewProgram,
			Severity: domain.SeverityHigh,
			After:    describeProgram(cur),
			Detail:   "no previous observation existed",
		})
		// StartedAt is a pointer because the source often omits a launch date.
		// Dereferencing it unconditionally crashed on the first program that did
		// not have one, which is common.
		if cur.StartedAt != nil && !cur.StartedAt.IsZero() {
			out.Changes = append(out.Changes, domain.Change{
				Kind:     domain.ChangeFirstSeen,
				Severity: domain.SeverityLow,
				Field:    "started_at",
				After:    cur.StartedAt.Format(time.RFC3339),
				Detail:   "source reports a launch date",
			})
		}
		out.Changes = domain.SortChanges(out.Changes)
		return out
	}

	out.FirstSeenAt = firstNonZero(prev.FirstSeenAt, prev.LastSeenAt, now)

	if cur.ScopeFingerprint != prev.ScopeFingerprint {
		out.Changes = append(out.Changes, scopeChanges(prev, cur)...)
	}
	if cur.RequirementFingerprint != prev.RequirementFingerprint {
		out.Changes = append(out.Changes, requirementChanges(prev, cur)...)
	}
	if cur.MetadataFingerprint != prev.MetadataFingerprint {
		out.Changes = append(out.Changes, metadataChanges(prev, cur)...)
	}

	// Lifecycle transitions are compared directly rather than through the
	// metadata fingerprint, because their severity depends on the direction of
	// travel: a program coming back to life is far more interesting than one
	// being paused.
	out.Changes = append(out.Changes, stateChanges(prev, cur)...)

	out.Changes = domain.SortChanges(out.Changes)
	return out
}

// scopeChanges compares the in-scope asset sets.
//
// Added and removed assets are reported individually, and separately by kind,
// because "an API was added" is the single most actionable change this system
// can observe and must not be buried inside a generic scope-changed event.
func scopeChanges(prev, cur domain.Program) domain.ChangeSet {
	var out domain.ChangeSet

	prevScope := prev.InScopeTargets()
	curScope := cur.InScopeTargets()

	// diffTargets reports the members of its first argument that are absent
	// from the second, so the arguments are ordered by what is being sought.
	added := diffTargets(curScope, prevScope)
	removed := diffTargets(prevScope, curScope)

	if len(added) > 0 {
		out = append(out, domain.Change{
			Kind:     domain.ChangeTargetAdded,
			Severity: domain.SeverityMedium,
			Assets:   identifiers(added),
			Detail:   fmt.Sprintf("%d asset(s) added to scope", len(added)),
		})
		out = append(out, kindSpecific(added, domain.ChangeTargetAdded,
			domain.KindAPI, domain.ChangeAPIAdded,
			domain.KindRepository, domain.ChangeRepositoryAdded,
			domain.KindMobile, domain.ChangeMobileAdded,
		)...)
	}
	if len(removed) > 0 {
		out = append(out, domain.Change{
			Kind:     domain.ChangeTargetRemoved,
			Severity: domain.SeverityLow,
			Assets:   identifiers(removed),
			Detail:   fmt.Sprintf("%d asset(s) removed from scope", len(removed)),
		})
		out = append(out, kindSpecific(removed, domain.ChangeTargetRemoved,
			domain.KindAPI, domain.ChangeAPIRemoved,
			domain.KindRepository, domain.ChangeRepositoryRemoved,
		)...)
	}
	if len(added) > 0 || len(removed) > 0 {
		out = append(out, domain.Change{
			Kind:     domain.ChangeScopeChanged,
			Severity: domain.SeverityMedium,
			Before:   strconv.Itoa(len(prevScope)) + " assets",
			After:    strconv.Itoa(len(curScope)) + " assets",
		})
	}

	// The technical surface is derived from the assets, so it is compared here
	// rather than under the metadata fingerprint. A new API is a change in what
	// can be tested, which is the single most actionable thing to report, and it
	// would otherwise be reported only as an anonymous asset addition.
	if !prev.SurfaceTags.Equal(cur.SurfaceTags) {
		out = append(out, domain.Change{
			Kind:     domain.ChangeSurfaceChanged,
			Severity: domain.SeverityMedium,
			Field:    "surface",
			Before:   describeTags(prev.SurfaceTags),
			After:    describeTags(cur.SurfaceTags),
		})
	}
	return out
}

// describeTags renders a tag set for a change record.
func describeTags(t domain.Tags) string {
	if len(t) == 0 {
		return "none"
	}
	return t.Join()
}

// kindSpecific emits per-kind events for the most actionable asset kinds.
func kindSpecific(targets domain.Targets, generic domain.ChangeKind, pairs ...any) domain.ChangeSet {
	var out domain.ChangeSet
	for i := 0; i+1 < len(pairs); i += 2 {
		kind, ok := pairs[i].(domain.TargetKind)
		if !ok {
			continue
		}
		event, ok := pairs[i+1].(domain.ChangeKind)
		if !ok {
			continue
		}
		matched := targets.OfKind(kind)
		if len(matched) == 0 {
			continue
		}
		severity := domain.SeverityMedium
		if generic == domain.ChangeTargetRemoved {
			// Losing scope is less actionable than gaining it.
			severity = domain.SeverityLow
		}
		out = append(out, domain.Change{
			Kind:     event,
			Severity: severity,
			Field:    string(kind),
			Assets:   identifiers(matched),
			Detail:   string(kind) + " " + verbFor(generic) + " scope",
		})
	}
	return out
}

func verbFor(kind domain.ChangeKind) string {
	if kind == domain.ChangeTargetRemoved {
		return "removed from"
	}
	return "added to"
}

// requirementChanges compares access gates and participation constraints.
//
// These are compared field by field rather than by fingerprint alone so that the
// change can be explained. A lowered reputation requirement is a materially
// different event from a raised one, even though both alter the same field.
func requirementChanges(prev, cur domain.Program) domain.ChangeSet {
	var out domain.ChangeSet

	if prev.Reputation.Present != cur.Reputation.Present || prev.Reputation.Points != cur.Reputation.Points {
		severity := domain.SeverityMedium
		out = append(out, domain.Change{
			Kind:     domain.ChangeReputationChanged,
			Severity: severity,
			Field:    "reputation",
			Before:   describeReputation(prev.Reputation),
			After:    describeReputation(cur.Reputation),
		})
	}
	if prev.Fee.Present != cur.Fee.Present || prev.Fee.USD != cur.Fee.USD {
		out = append(out, domain.Change{
			Kind:     domain.ChangeFeeChanged,
			Severity: domain.SeverityMedium,
			Field:    "submission_fee",
			Before:   describeFee(prev.Fee),
			After:    describeFee(cur.Fee),
		})
	}
	if prev.KYC != cur.KYC {
		severity := domain.SeverityMedium
		out = append(out, domain.Change{
			Kind:     domain.ChangeKYCChanged,
			Severity: severity,
			Field:    "kyc",
			Before:   "kyc=" + prev.KYC.String(),
			After:    "kyc=" + cur.KYC.String(),
		})
	}
	if prev.POC != cur.POC {
		out = append(out, domain.Change{
			Kind:     domain.ChangePOCChanged,
			Severity: domain.SeverityLow,
			Field:    "poc",
			Before:   "poc=" + prev.POC.String(),
			After:    "poc=" + cur.POC.String(),
		})
	}
	if prev.ProgramRules != cur.ProgramRules {
		out = append(out, domain.Change{
			Kind:     domain.ChangeRequirementChanged,
			Severity: domain.SeverityMedium,
			Field:    "program_rules",
			Detail:   "participation rules changed",
		})
	}
	if prev.ScopeNotes != cur.ScopeNotes {
		out = append(out, domain.Change{
			Kind:     domain.ChangeScopeReviewChanged,
			Severity: domain.SeverityMedium,
			Field:    "scope_review",
			Detail:   "the stated in-scope vulnerability list changed",
		})
	}
	return out
}

// metadataChanges compares identity, classification, bounty, and crypto posture.
func metadataChanges(prev, cur domain.Program) domain.ChangeSet {
	var out domain.ChangeSet

	if !sameFloat(prev.MinBountyUSD, cur.MinBountyUSD) || !sameFloat(prev.MaxBountyUSD, cur.MaxBountyUSD) {
		// A raised ceiling is more actionable than a lowered floor, so the
		// direction determines severity.
		raised := floatOrZero(cur.MaxBountyUSD) > floatOrZero(prev.MaxBountyUSD)
		severity := domain.SeverityLow
		if raised {
			severity = domain.SeverityMedium
		}
		out = append(out, domain.Change{
			Kind:     domain.ChangeBountyChanged,
			Severity: severity,
			Field:    "bounty",
			Before:   describeBounty(prev),
			After:    describeBounty(cur),
		})
	}
	if prev.CryptoKind != cur.CryptoKind {
		out = append(out, domain.Change{
			Kind:     domain.ChangeCryptoReclassified,
			Severity: domain.SeverityMedium,
			Field:    "crypto_kind",
			Before:   string(prev.CryptoKind),
			After:    string(cur.CryptoKind),
		})
	}
	if len(out) > 0 {
		out = append(out, domain.Change{
			Kind:     domain.ChangeMetadataChanged,
			Severity: domain.SeverityLow,
			Detail:   "classification or bounty metadata changed",
		})
	}
	return out
}

// stateChanges compares lifecycle state directly.
func stateChanges(prev, cur domain.Program) domain.ChangeSet {
	if prev.State == cur.State {
		return nil
	}
	out := domain.ChangeSet{{
		Kind:     domain.ChangeStateChanged,
		Severity: domain.SeverityLow,
		Field:    "state",
		Before:   string(prev.State),
		After:    string(cur.State),
	}}

	switch {
	case prev.State == domain.StatePaused && cur.State == domain.StateLive,
		prev.State == domain.StateEnded && cur.State == domain.StateLive,
		prev.State == domain.StateLive && cur.State == domain.StateNew:
		// Coming back to life after a gap is the highest-value event this
		// system can report: a reopened program is a fresh window that other
		// researchers have not yet seen.
		out = append(out, domain.Change{
			Kind:     domain.ChangeProgramReactivated,
			Severity: domain.SeverityHigh,
			Field:    "state",
			Before:   string(prev.State),
			After:    string(cur.State),
			Detail:   "the program is accepting reports again",
		})
	case cur.State == domain.StateEnded:
		out = append(out, domain.Change{
			Kind:     domain.ChangeProgramEnded,
			Severity: domain.SeverityLow,
			Field:    "state",
			After:    string(cur.State),
			Detail:   "the program will not accept further reports",
		})
	case cur.State == domain.StatePaused:
		out = append(out, domain.Change{
			Kind:     domain.ChangeProgramPaused,
			Severity: domain.SeverityLow,
			Field:    "state",
			After:    string(cur.State),
			Detail:   "the program is temporarily not accepting reports",
		})
	}
	return out
}

// diffTargets returns the targets present in a but not in b.
//
// Matching is by kind and normalized identifier so that a cosmetic rename of a
// label, or a change in URL formatting, does not register as a scope change.
func diffTargets(a, b domain.Targets) domain.Targets {
	index := make(map[string]struct{}, len(b))
	for _, t := range b {
		index[targetKey(t)] = struct{}{}
	}
	out := make(domain.Targets, 0)
	for _, t := range a {
		if _, dup := index[targetKey(t)]; dup {
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetKey(t domain.Target) string {
	return string(t.Kind) + "\x00" + normalizeIdentifier(t.Identifier)
}

func identifiers(ts domain.Targets) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		id := t.Identifier
		if id == "" {
			id = t.Label
		}
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func normalizeIdentifier(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func describeReputation(g domain.ReputationGate) string {
	switch g.Present {
	case domain.TriYes:
		return strconv.Itoa(g.Points) + " reputation points"
	case domain.TriNo:
		return "no reputation required"
	default:
		return "unknown"
	}
}

func describeFee(g domain.FeeGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("$%.2f", g.USD)
	case domain.TriNo:
		return "no submission fee"
	default:
		return "unknown"
	}
}

func describeBounty(p domain.Program) string {
	switch {
	case p.MinBountyUSD != nil && p.MaxBountyUSD != nil:
		return fmt.Sprintf("$%.0f - $%.0f", *p.MinBountyUSD, *p.MaxBountyUSD)
	case p.MaxBountyUSD != nil:
		return "up to $" + strconv.FormatFloat(*p.MaxBountyUSD, 'f', -1, 64)
	default:
		return "unstated"
	}
}

func describeProgram(p domain.Program) string {
	parts := []string{p.Name}
	if p.State != domain.StateUnknown {
		parts = append(parts, string(p.State))
	}
	if p.MaxBountyUSD != nil {
		parts = append(parts, "up to $"+strconv.FormatFloat(*p.MaxBountyUSD, 'f', -1, 64))
	}
	return strings.Join(parts, ", ")
}

func sameFloat(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func floatOrZero(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func firstNonZero(values ...time.Time) time.Time {
	for _, v := range values {
		if !v.IsZero() {
			return v
		}
	}
	return time.Time{}
}
