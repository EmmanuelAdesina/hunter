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
	"sort"
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

	// The surface comparison is unconditional. See surfaceChange: a relabelled
	// asset moves the surface without moving the asset set, and the fingerprint
	// cannot see it.
	if !prev.SurfaceTags.Equal(cur.SurfaceTags) {
		out.Changes = append(out.Changes, surfaceChange(prev.SurfaceTags, cur.SurfaceTags))
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
			Kind:      domain.ChangeTargetAdded,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionImproved,
			Assets:    identifiers(added),
			Detail:    fmt.Sprintf("%d asset(s) added to scope", len(added)),
		})
		out = append(out, kindSpecific(added, domain.ChangeTargetAdded,
			domain.KindAPI, domain.ChangeAPIAdded,
			domain.KindRepository, domain.ChangeRepositoryAdded,
			domain.KindMobile, domain.ChangeMobileAdded,
		)...)
	}
	if len(removed) > 0 {
		out = append(out, domain.Change{
			Kind:      domain.ChangeTargetRemoved,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionDegraded,
			Assets:    identifiers(removed),
			Detail:    fmt.Sprintf("%d asset(s) removed from scope", len(removed)),
		})
		out = append(out, kindSpecific(removed, domain.ChangeTargetRemoved,
			domain.KindAPI, domain.ChangeAPIRemoved,
			domain.KindRepository, domain.ChangeRepositoryRemoved,
			domain.KindMobile, domain.ChangeMobileRemoved,
		)...)
	}

	// An asset that keeps its identifier but changes its in-scope flag is a scope
	// change that an in-scope-only comparison cannot see at all.
	//
	// The scope fingerprint deliberately hashes only in-scope assets, so moving an
	// asset out of scope is visible as a removal and moving one in is visible as
	// an addition. What is NOT visible is an asset the source lists once whose
	// flag flips while it was already out of scope in both observations - the
	// set is identical either way. That case is compared explicitly here so that
	// "the same hostname just became testable" is never silently dropped.
	out = append(out, scopeFlagChanges(prev, cur)...)

	if len(added) > 0 || len(removed) > 0 {
		out = append(out, domain.Change{
			Kind:      domain.ChangeScopeChanged,
			Severity:  domain.SeverityMedium,
			Direction: directionOf(len(added), len(removed)),
			Before:    strconv.Itoa(len(prevScope)) + " assets",
			After:     strconv.Itoa(len(curScope)) + " assets",
		})
	}

	// The technical surface is derived from the assets, so it is compared here
	// rather than under the metadata fingerprint. A new API is a change in what
	// can be tested, which is the single most actionable thing to report, and it
	// would otherwise be reported only as an anonymous asset addition.
	if !prev.SurfaceTags.Equal(cur.SurfaceTags) {
		out = append(out, surfaceChange(prev.SurfaceTags, cur.SurfaceTags))
	}
	return out
}

// surfaceChange builds the surface event.
//
// It is exported through Compare unconditionally rather than behind the scope
// fingerprint: a program can keep the exact same assets and change what can be
// tested against them - a hostname reclassified from web to API - and gating the
// comparison on the fingerprint would make that invisible, because the asset set
// did not move.
func surfaceChange(prev, cur domain.Tags) domain.Change {
	return domain.Change{
		Kind:      domain.ChangeSurfaceChanged,
		Severity:  domain.SeverityMedium,
		Direction: surfaceDirection(prev, cur),
		Field:     "surface",
		Before:    describeTags(prev),
		After:     describeTags(cur),
	}
}

// scopeFlagChanges reports assets whose in-scope flag moved while their
// identifier stayed the same.
//
// Both observations are searched over all assets, not just in-scope ones, because
// the interesting case is precisely the one the scope fingerprint cannot express:
// an asset that was out of scope and is now in scope has the same identifier in
// both records and the same effect on the in-scope set, so it produces no
// fingerprint change and no add or remove.
func scopeFlagChanges(prev, cur domain.Program) domain.ChangeSet {
	prevFlags := scopeFlags(prev.Targets)
	curFlags := scopeFlags(cur.Targets)

	inScope := make([]string, 0, 4)
	outOfScope := make([]string, 0, 4)
	for key, wasIn := range prevFlags {
		nowIn, ok := curFlags[key]
		if !ok || wasIn == nowIn {
			continue
		}
		if nowIn {
			inScope = append(inScope, displayIdentifier(cur.Targets, key))
		} else {
			outOfScope = append(outOfScope, displayIdentifier(prev.Targets, key))
		}
	}
	// An asset that appeared in the current record rather than flipping flag is
	// already reported as an addition, and one that vanished as a removal.
	sort.Strings(inScope)
	sort.Strings(outOfScope)

	var out domain.ChangeSet
	if len(inScope) > 0 {
		out = append(out, domain.Change{
			Kind:      domain.ChangeTargetInScope,
			Severity:  domain.SeverityHigh,
			Direction: domain.DirectionImproved,
			Field:     "in_scope",
			Assets:    inScope,
			Detail:    "an asset already listed for this program became testable",
		})
	}
	if len(outOfScope) > 0 {
		out = append(out, domain.Change{
			Kind:      domain.ChangeTargetOutOfScope,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionDegraded,
			Field:     "in_scope",
			Assets:    outOfScope,
			Detail:    "an asset is no longer testable",
		})
	}
	return out
}

func scopeFlags(ts domain.Targets) map[string]bool {
	out := make(map[string]bool, len(ts))
	for _, t := range ts {
		out[targetKey(t)] = t.InScope
	}
	return out
}

func displayIdentifier(ts domain.Targets, key string) string {
	for _, t := range ts {
		if targetKey(t) != key {
			continue
		}
		if t.Identifier != "" {
			return t.Identifier
		}
		return t.Label
	}
	return key
}

// directionOf resolves the net direction of a set-size change.
func directionOf(added, removed int) domain.Direction {
	switch {
	case added > removed:
		return domain.DirectionImproved
	case removed > added:
		return domain.DirectionDegraded
	default:
		return domain.DirectionNeutral
	}
}

// surfaceDirection resolves which way the testable surface moved.
//
// The comparison is on the profile's own vocabulary, so "gained an API" is
// visible even when the underlying asset set is unchanged - for instance when a
// program re-labels an existing hostname.
func surfaceDirection(prev, cur domain.Tags) domain.Direction {
	gained := len(cur.Subtract(prev))
	lost := len(prev.Subtract(cur))
	return directionOf(gained, lost)
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
// change can be explained, and each field emits both an undirected summary and a
// directional event. A lowered reputation requirement is a materially different
// event from a raised one - one opens the program to a researcher who could not
// reach it, the other closes it - and emitting only "the reputation changed"
// would leave every consumer to re-derive the sign from two formatted strings.
func requirementChanges(prev, cur domain.Program) domain.ChangeSet {
	var out domain.ChangeSet

	if prev.Reputation.Present != cur.Reputation.Present || prev.Reputation.Points != cur.Reputation.Points {
		out = append(out, domain.Change{
			Kind:      domain.ChangeReputationChanged,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "reputation",
			Before:    describeReputation(prev.Reputation),
			After:     describeReputation(cur.Reputation),
		})
		before, after, ok := reputationDelta(prev.Reputation, cur.Reputation)
		if ok {
			out = append(out, domain.Change{
				Kind:      before.kind,
				Severity:  before.severity,
				Direction: before.direction,
				Field:     "reputation",
				Before:    before.text,
				After:     after,
				Detail:    before.detail,
			})
		}
	}
	if prev.Fee.Present != cur.Fee.Present || prev.Fee.USD != cur.Fee.USD {
		out = append(out, domain.Change{
			Kind:      domain.ChangeFeeChanged,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "submission_fee",
			Before:    describeFee(prev.Fee),
			After:     describeFee(cur.Fee),
		})
		if k, sev, dir, detail := feeDirection(prev.Fee, cur.Fee); k != "" {
			out = append(out, domain.Change{
				Kind:      k,
				Severity:  sev,
				Direction: dir,
				Field:     "submission_fee",
				Before:    describeFee(prev.Fee),
				After:     describeFee(cur.Fee),
				Detail:    detail,
			})
		}
	}
	if prev.KYC != cur.KYC {
		out = append(out, domain.Change{
			Kind:      domain.ChangeKYCChanged,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "kyc",
			Before:    "kyc=" + prev.KYC.String(),
			After:     "kyc=" + cur.KYC.String(),
		})
		// KYC only has a direction when both sides are known. A gate becoming
		// unknown is not the same as a gate being removed, and treating it as one
		// would raise an alert on a parser regression.
		if prev.KYC.Known() && cur.KYC.Known() {
			k, sev, dir := domain.ChangeKYCRequired, domain.SeverityLow, domain.DirectionDegraded
			if cur.KYC.No() {
				k, sev, dir = domain.ChangeKYCRemoved, domain.SeverityMedium, domain.DirectionImproved
			}
			out = append(out, domain.Change{
				Kind:      k,
				Severity:  sev,
				Direction: dir,
				Field:     "kyc",
				Before:    "kyc=" + prev.KYC.String(),
				After:     "kyc=" + cur.KYC.String(),
				Detail:    "identity verification requirement changed",
			})
		}
	}
	if prev.POC != cur.POC {
		out = append(out, domain.Change{
			Kind:      domain.ChangePOCChanged,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionUnknown,
			Field:     "poc",
			Before:    "poc=" + prev.POC.String(),
			After:     "poc=" + cur.POC.String(),
		})
		if prev.POC.Known() && cur.POC.Known() {
			k, sev, dir := domain.ChangePOCRequired, domain.SeverityLow, domain.DirectionDegraded
			if cur.POC.No() {
				k, sev, dir = domain.ChangePOCRemoved, domain.SeverityMedium, domain.DirectionImproved
			}
			out = append(out, domain.Change{
				Kind:      k,
				Severity:  sev,
				Direction: dir,
				Field:     "poc",
				Before:    "poc=" + prev.POC.String(),
				After:     "poc=" + cur.POC.String(),
				Detail:    "proof-of-concept requirement changed",
			})
		}
	}
	if prev.ProgramRules != cur.ProgramRules {
		out = append(out, domain.Change{
			Kind:      domain.ChangeRequirementChanged,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "program_rules",
			Detail:    "participation rules changed",
		})
	}
	if prev.ScopeNotes != cur.ScopeNotes {
		out = append(out, domain.Change{
			Kind:      domain.ChangeScopeReviewChanged,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "scope_review",
			Detail:    "the stated in-scope vulnerability list changed; the wording is not classified",
		})
	}
	return out
}

// directionalChange is the resolved direction of one field movement.
type directionalChange struct {
	kind      domain.ChangeKind
	severity  domain.Severity
	direction domain.Direction
	text      string
	detail    string
}

// reputationDelta resolves a reputation movement.
//
// A gate becoming absent is a removal, not a raise to zero, because the two mean
// different things to a researcher and the rendered text says which.
func reputationDelta(prev, cur domain.ReputationGate) (directionalChange, string, bool) {
	switch {
	case prev.Points > cur.Points:
		return directionalChange{
			kind: domain.ChangeReputationLowered, severity: domain.SeverityMedium,
			direction: domain.DirectionImproved,
			text:      describeReputation(prev),
			detail:    "the reputation requirement was lowered, widening who can submit",
		}, describeReputation(cur), true
	case prev.Points < cur.Points:
		return directionalChange{
			kind: domain.ChangeReputationRaised, severity: domain.SeverityLow,
			direction: domain.DirectionDegraded,
			text:      describeReputation(prev),
			detail:    "the reputation requirement was raised, narrowing who can submit",
		}, describeReputation(cur), true
	case prev.Present == domain.TriYes && cur.Present != domain.TriYes:
		return directionalChange{
			kind: domain.ChangeReputationLowered, severity: domain.SeverityMedium,
			direction: domain.DirectionImproved,
			text:      describeReputation(prev),
			detail:    "the reputation requirement was removed",
		}, describeReputation(cur), true
	case prev.Present != domain.TriYes && cur.Present == domain.TriYes:
		return directionalChange{
			kind: domain.ChangeReputationRaised, severity: domain.SeverityLow,
			direction: domain.DirectionDegraded,
			text:      describeReputation(prev),
			detail:    "a reputation requirement was introduced",
		}, describeReputation(cur), true
	}
	return directionalChange{}, "", false
}

// feeDirection resolves a submission-fee movement.
//
// The platform states fees in the account currency, so a non-zero fee is carried
// as unknown rather than as an amount. An unknown-to-unknown comparison has no
// direction, and neither has unknown-to-present: the system cannot claim a fee
// was introduced when it simply started being readable.
func feeDirection(prev, cur domain.FeeGate) (domain.ChangeKind, domain.Severity, domain.Direction, string) {
	if !prev.Known() || !cur.Known() {
		return "", domain.SeverityLow, domain.DirectionUnknown, ""
	}
	// The zero cases are tested first. A fee dropping to zero is a removal, not
	// merely a reduction, and the two mean different things to a researcher: one
	// makes a speculative report free, the other only makes it cheaper.
	switch {
	case prev.USD > 0 && cur.USD == 0:
		return domain.ChangeFeeRemoved, domain.SeverityMedium, domain.DirectionImproved,
			"the submission fee was removed, making a speculative report free"
	case prev.USD == 0 && cur.USD > 0:
		return domain.ChangeFeeIntroduced, domain.SeverityLow, domain.DirectionDegraded,
			"a submission fee was introduced"
	case prev.USD > cur.USD:
		return domain.ChangeFeeReduced, domain.SeverityMedium, domain.DirectionImproved,
			"the submission fee was reduced, lowering the cost of a speculative report"
	case prev.USD < cur.USD:
		return domain.ChangeFeeIncreased, domain.SeverityLow, domain.DirectionDegraded,
			"the submission fee was increased"
	}
	return "", domain.SeverityLow, domain.DirectionUnknown, ""
}

// metadataChanges compares identity, classification, bounty, and crypto posture.
func metadataChanges(prev, cur domain.Program) domain.ChangeSet {
	var out domain.ChangeSet

	if !sameFloat(prev.MinBountyUSD, cur.MinBountyUSD) || !sameFloat(prev.MaxBountyUSD, cur.MaxBountyUSD) {
		// A raised ceiling is more actionable than a lowered floor, so the
		// direction determines severity.
		raised := floatOrZero(cur.MaxBountyUSD) > floatOrZero(prev.MaxBountyUSD)
		severity := domain.SeverityLow
		dir := domain.DirectionDegraded
		if raised {
			severity = domain.SeverityMedium
			dir = domain.DirectionImproved
		}
		out = append(out, domain.Change{
			Kind:      domain.ChangeBountyChanged,
			Severity:  severity,
			Direction: dir,
			Field:     "bounty",
			Before:    describeBounty(prev),
			After:     describeBounty(cur),
		})
		k := domain.ChangeBountyLowered
		if raised {
			k = domain.ChangeBountyRaised
		}
		out = append(out, domain.Change{
			Kind:      k,
			Severity:  severity,
			Direction: dir,
			Field:     "bounty",
			Before:    describeBounty(prev),
			After:     describeBounty(cur),
			Detail:    "the stated bounty ceiling moved",
		})
	}
	if prev.CryptoKind != cur.CryptoKind {
		out = append(out, domain.Change{
			Kind:      domain.ChangeCryptoReclassified,
			Severity:  domain.SeverityMedium,
			Direction: domain.DirectionUnknown,
			Field:     "crypto_kind",
			Before:    string(prev.CryptoKind),
			After:     string(cur.CryptoKind),
		})
	}
	if len(out) > 0 {
		out = append(out, domain.Change{
			Kind:      domain.ChangeMetadataChanged,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionUnknown,
			Detail:    "classification or bounty metadata changed",
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
		Kind:      domain.ChangeStateChanged,
		Severity:  domain.SeverityLow,
		Direction: domain.DirectionUnknown,
		Field:     "state",
		Before:    string(prev.State),
		After:     string(cur.State),
	}}

	switch {
	case prev.State == domain.StatePaused && cur.State == domain.StateLive,
		prev.State == domain.StateEnded && cur.State == domain.StateLive,
		prev.State == domain.StateLive && cur.State == domain.StateNew:
		// Coming back to life after a gap is the highest-value event this
		// system can report: a reopened program is a fresh window that other
		// researchers have not yet seen.
		out = append(out, domain.Change{
			Kind:      domain.ChangeProgramReactivated,
			Severity:  domain.SeverityHigh,
			Direction: domain.DirectionImproved,
			Field:     "state",
			Before:    string(prev.State),
			After:     string(cur.State),
			Detail:    "the program is accepting reports again",
		})
	case cur.State == domain.StateEnded:
		out = append(out, domain.Change{
			Kind:      domain.ChangeProgramEnded,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionDegraded,
			Field:     "state",
			After:     string(cur.State),
			Detail:    "the program will not accept further reports",
		})
	case cur.State == domain.StatePaused:
		out = append(out, domain.Change{
			Kind:      domain.ChangeProgramPaused,
			Severity:  domain.SeverityLow,
			Direction: domain.DirectionDegraded,
			Field:     "state",
			After:     string(cur.State),
			Detail:    "the program is temporarily not accepting reports",
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
