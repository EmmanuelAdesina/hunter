package domain

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ChangeKind identifies one semantic change between two observations of a
// program.
//
// The vocabulary is open: the kind is stored as a string so a new source or a
// new policy can introduce one without a schema migration. Change detection
// never compares page timestamps to decide *what* changed; it compares content.
type ChangeKind string

const (
	ChangeNewProgram         ChangeKind = "NEW_PROGRAM"
	ChangeFirstSeen          ChangeKind = "FIRST_SEEN"
	ChangeProgramReactivated ChangeKind = "PROGRAM_REACTIVATED"
	ChangeProgramPaused      ChangeKind = "PROGRAM_PAUSED"
	ChangeProgramEnded       ChangeKind = "PROGRAM_ENDED"
	ChangeStateChanged       ChangeKind = "STATE_CHANGED"
	ChangeScopeChanged       ChangeKind = "SCOPE_CHANGED"
	ChangeTargetAdded        ChangeKind = "TARGET_ADDED"
	ChangeTargetRemoved      ChangeKind = "TARGET_REMOVED"
	ChangeTargetInScope      ChangeKind = "ASSET_MOVED_IN_SCOPE"
	ChangeTargetOutOfScope   ChangeKind = "ASSET_MOVED_OUT_OF_SCOPE"
	ChangeAPIAdded           ChangeKind = "API_ADDED"
	ChangeAPIRemoved         ChangeKind = "API_REMOVED"
	ChangeRepositoryAdded    ChangeKind = "REPOSITORY_ADDED"
	ChangeRepositoryRemoved  ChangeKind = "REPOSITORY_REMOVED"
	ChangeMobileAdded        ChangeKind = "MOBILE_ADDED"
	ChangeMobileRemoved      ChangeKind = "MOBILE_REMOVED"
	ChangeRequirementChanged ChangeKind = "REQUIREMENT_CHANGED"
	ChangeKYCChanged         ChangeKind = "KYC_CHANGED"
	ChangeKYCRequired        ChangeKind = "KYC_REQUIRED"
	ChangeKYCRemoved         ChangeKind = "KYC_REMOVED"
	ChangeReputationChanged  ChangeKind = "REPUTATION_CHANGED"
	ChangeReputationLowered  ChangeKind = "REPUTATION_LOWERED"
	ChangeReputationRaised   ChangeKind = "REPUTATION_RAISED"
	ChangeFeeChanged         ChangeKind = "SUBMISSION_FEE_CHANGED"
	ChangeFeeReduced         ChangeKind = "FEE_REDUCED"
	ChangeFeeIncreased       ChangeKind = "FEE_INCREASED"
	ChangeFeeRemoved         ChangeKind = "FEE_REMOVED"
	ChangeFeeIntroduced      ChangeKind = "FEE_INTRODUCED"
	ChangePOCChanged         ChangeKind = "POC_CHANGED"
	ChangePOCRequired        ChangeKind = "POC_REQUIRED"
	ChangePOCRemoved         ChangeKind = "POC_REMOVED"
	ChangeBountyChanged      ChangeKind = "BOUNTY_CHANGED"
	ChangeBountyRaised       ChangeKind = "BOUNTY_CEILING_RAISED"
	ChangeBountyLowered      ChangeKind = "BOUNTY_CEILING_LOWERED"
	ChangeScopeReviewChanged ChangeKind = "SCOPE_REVIEW_CHANGED"
	ChangeMetadataChanged    ChangeKind = "METADATA_CHANGED"
	ChangeCryptoReclassified ChangeKind = "CRYPTO_RECLASSIFIED"
	ChangeSurfaceChanged     ChangeKind = "SURFACE_CHANGED"
	ChangeSubmissionsChanged ChangeKind = "SUBMISSIONS_CHANGED"
)

// Directional change kinds.
//
// A single field can move in two opposite directions, and only one of them
// usually makes the program worth interrupting for. Recording both under one
// undirected kind forces every downstream consumer to re-derive the sign from
// two human-readable strings, which is exactly the kind of inference that
// eventually disagrees with itself between the renderer, the scorer, and the
// alert trigger.
//
// These kinds exist alongside the undirected ones rather than replacing them.
// The undirected kind remains the summary - "the submission fee changed" - while
// the directional kind carries the sign. Both are emitted, so a consumer that
// only cares that something moved does not have to know about direction at all.

// Alert-worthy directions, stated once so that trigger selection, rendering, and
// scoring cannot drift apart.
const (
// Directional access kinds.
//
// Lowering a requirement, removing KYC, or removing a fee all make a program
// reachable for a researcher who could not previously reach it.
)

// alertOn reports whether a kind is worth interrupting for on its own.
//
// The rule is directional and structural rather than per-kind: a change that
// improves reachability or adds testable surface alerts; a change that removes
// either is recorded and never alerts alone. That is what keeps the channel
// meaningful without maintaining a hand-written list that a new kind could
// silently be left out of.
func (k ChangeKind) Alertable() bool { return k.alertOn() }

// RecordOnly reports whether a kind is deliberately never alerted on.
//
// It is exported so that the classification can be verified rather than
// inferred: a kind that is neither alertable nor record-only is unclassified, and
// unclassified is a bug rather than a default.
func (k ChangeKind) RecordOnly() bool { return k.recordOnly() }

// Classified reports whether the kind has been placed on one side of the
// alertable/record-only divide.
func (k ChangeKind) Classified() bool { return k.alertOn() || k.recordOnly() }

func (k ChangeKind) alertOn() bool {
	switch k {
	case ChangeTargetAdded, ChangeAPIAdded, ChangeRepositoryAdded, ChangeMobileAdded,
		ChangeTargetInScope,
		ChangeReputationLowered, ChangeKYCRemoved, ChangeFeeReduced, ChangeFeeRemoved,
		ChangePOCRemoved,
		ChangeBountyRaised,
		ChangeProgramReactivated,
		ChangeScopeReviewChanged,
		ChangeCryptoReclassified:
		return true
	default:
		return false
	}
}

// recordOnly reports whether a kind is deliberately never alerted on.
//
// Losing access is not an opening. It is still recorded, because "the program I
// was watching just closed its API scope" is something a researcher needs to
// know, and because the next comparison depends on the new baseline.
func (k ChangeKind) recordOnly() bool {
	switch k {
	case ChangeTargetRemoved, ChangeAPIRemoved, ChangeRepositoryRemoved, ChangeMobileRemoved,
		ChangeTargetOutOfScope,
		ChangeReputationRaised, ChangeKYCRequired, ChangeFeeIncreased, ChangeFeeIntroduced,
		ChangePOCRequired,
		ChangeBountyLowered,
		ChangeProgramPaused, ChangeProgramEnded,
		ChangeSubmissionsChanged, ChangeFirstSeen,
		ChangeMetadataChanged, ChangeRequirementChanged,
		ChangeReputationChanged, ChangeFeeChanged, ChangeKYCChanged,
		ChangePOCChanged, ChangeBountyChanged, ChangeStateChanged:
		return true
	default:
		return false
	}
}

// Severity ranks how much a change matters for alerting.
type Severity string

const (
	// SeverityLow is recorded in state but never alerts on its own.
	SeverityLow Severity = "low"
	// SeverityMedium alerts only when it adds attack surface.
	SeverityMedium Severity = "medium"
	// SeverityHigh always alerts for an eligible program.
	SeverityHigh Severity = "high"
)

// rank orders severities for comparison.
func (s Severity) rank() int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return s.rank() >= other.rank() }

// Change is one detected semantic difference.
type Change struct {
	Kind     ChangeKind `json:"kind"`
	Severity Severity   `json:"severity"`

	// Field names the specific field or asset that changed, when applicable.
	Field string `json:"field,omitempty"`

	// Before and After render the previous and current values. They are
	// human-readable on purpose: this record is meant to be read in an email.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`

	// Assets lists the specific assets involved, e.g. added API targets.
	Assets []string `json:"assets,omitempty"`

	// Direction states which way the change moved, for changes where direction
	// is meaningful. DirectionUnknown otherwise.
	Direction Direction `json:"direction,omitempty"`

	// Detail adds context for decisions that are not obvious from the fields.
	Detail string `json:"detail,omitempty"`
}

// Alertable reports whether this change alone is worth interrupting for.
//
// It is derived from the kind's direction rather than from its severity, so that
// a single rule governs which changes reach a channel. Severity still governs
// the profile's floor; this governs whether the kind is capable of alerting at
// all.
func (c Change) Alertable() bool {
	// These two kinds are summary events whose direction is genuinely either way:
	// "the scope changed" is emitted whether assets were added or only removed.
	// Letting them alert unconditionally would mean every scope reduction in the
	// catalogue reached the channel, which is precisely the noise the directional
	// split exists to remove.
	switch c.Kind {
	case ChangeScopeChanged, ChangeSurfaceChanged:
		return c.Direction == DirectionImproved
	}
	return c.Kind.Alertable()
}

// Improved reports whether the change moved in the researcher's favour.
func (c Change) Improved() bool { return c.Direction == DirectionImproved }

// Degraded reports whether the change moved against the researcher.
func (c Change) Degraded() bool { return c.Direction == DirectionDegraded }

// Describe renders one alert-ready line for the change.
func (c Change) Describe() string {
	var b strings.Builder
	symbol := map[Severity]string{
		SeverityHigh: "+", SeverityMedium: "~", SeverityLow: "-",
	}[c.Severity]
	b.WriteString(symbol)
	b.WriteString(" ")
	b.WriteString(string(c.Kind))
	switch {
	case c.Field != "":
		b.WriteString(" [")
		b.WriteString(c.Field)
		b.WriteString("]")
	}
	if len(c.Assets) > 0 {
		shown := c.Assets
		if len(shown) > 6 {
			shown = append(append([]string{}, shown[:6]...), fmt.Sprintf("(+%d more)", len(c.Assets)-6))
		}
		b.WriteString(": ")
		b.WriteString(strings.Join(shown, ", "))
	}
	switch {
	case c.Before != "" && c.After != "":
		b.WriteString(": ")
		b.WriteString(c.Before)
		b.WriteString(" -> ")
		b.WriteString(c.After)
	case c.After != "":
		b.WriteString(": ")
		b.WriteString(c.After)
	case c.Detail != "":
		b.WriteString(": ")
		b.WriteString(c.Detail)
	}
	return b.String()
}

// ChangeSet is an ordered collection of changes detected in one comparison.
type ChangeSet []Change

// Highest returns the most severe change in the set.
func (cs ChangeSet) Highest() Severity {
	best := SeverityLow
	for _, c := range cs {
		if c.Severity.rank() > best.rank() {
			best = c.Severity
		}
	}
	return best
}

// Contains reports whether the set contains a kind.
func (cs ChangeSet) Contains(k ChangeKind) bool {
	for _, c := range cs {
		if c.Kind == k {
			return true
		}
	}
	return false
}

// Kinds returns the distinct kinds present, sorted for stable output.
func (cs ChangeSet) Kinds() []string {
	out := make([]string, 0, len(cs))
	seen := make(map[string]struct{}, len(cs))
	for _, c := range cs {
		if _, dup := seen[string(c.Kind)]; dup {
			continue
		}
		seen[string(c.Kind)] = struct{}{}
		out = append(out, string(c.Kind))
	}
	sort.Strings(out)
	return out
}

// Deltas projects the set onto its atomic directional evidence.
//
// The projection is total and loses nothing: every change either yields exactly
// one delta or is explicitly not a field movement. Recording the set rather than
// only the interesting parts is what lets a window claim to be reconstructable
// from observed facts, because a reader can see what was NOT directional too.
func (cs ChangeSet) Deltas() Deltas {
	out := make(Deltas, 0, len(cs))
	for _, c := range cs {
		d := Delta{
			Kind:      c.Kind,
			Field:     c.Field,
			Before:    c.Before,
			After:     c.After,
			Direction: c.Direction,
			Assets:    c.Assets,
			Basis:     c.Detail,
		}
		if d.Direction == "" {
			d.Direction = DirectionUnknown
		}
		out = append(out, d)
	}
	return out
}

// AlertableChanges returns the subset capable of raising an alert on their own.
func (cs ChangeSet) AlertableChanges() ChangeSet {
	out := make(ChangeSet, 0, len(cs))
	for _, c := range cs {
		if c.Alertable() {
			out = append(out, c)
		}
	}
	return out
}

// Empty reports whether the set holds no changes.
func (cs ChangeSet) Empty() bool { return len(cs) == 0 }

// Summary renders a compact comma-separated list of kinds, for logs.
func (cs ChangeSet) Summary() string {
	k := cs.Kinds()
	if len(k) > 4 {
		return fmt.Sprintf("%s(+%d more)", strings.Join(k[:4], ","), len(k)-4)
	}
	return strings.Join(k, ",")
}

// Diff is the full result of comparing a previous observation to a current one.
type Diff struct {
	ProgramID string `json:"program_id"`

	// Previous is nil when the program had never been observed before.
	Previous *Program `json:"-"`

	// IsNew reports that no previous observation existed.
	IsNew bool `json:"is_new"`

	// Changes is the detected set, ordered by severity then kind.
	Changes ChangeSet `json:"changes"`

	// FirstSeenAt carries forward from previous state for a known program.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// PreviousLastSeenAt is when the previous observation was made.
	PreviousLastSeenAt time.Time `json:"previous_last_seen_at"`
}

// AlertableMaterial reports whether the set contains a change that is both
// significant enough and capable of alerting on its own.
//
// It is deliberately stricter than Material. Material answers "is this worth
// recording", which is true of a scope reduction; AlertableMaterial answers "is
// this worth interrupting for", which is not. Using Material as the alert trigger
// would put every recorded removal on the channel.
func (cs ChangeSet) AlertableMaterial() bool {
	for _, c := range cs {
		if c.Severity.AtLeast(SeverityMedium) && c.Alertable() {
			return true
		}
	}
	return false
}

// Material reports whether the change set represents a change worth notifying
// about, independent of eligibility. Alert policy combines this with the
// eligibility decision.
func (d Diff) Material() bool {
	for _, c := range d.Changes {
		if c.Severity.AtLeast(SeverityMedium) {
			return true
		}
	}
	return false
}

// SortChanges orders by descending severity, then kind, then field, so that the
// most important change is always rendered first in an alert.
func SortChanges(cs ChangeSet) ChangeSet {
	out := append(ChangeSet(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := out[i].Severity.rank(), out[j].Severity.rank(); ri != rj {
			return ri > rj
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Field < out[j].Field
	})
	return out
}

// ChangeInterval returns the observation interval that bounds a change of the
// given kind, read from a freshness set.
//
// Each kind belongs to exactly one fingerprint group, so the interval that bounds
// it is the one recorded for that group. A kind with no group cannot be bounded
// and reports false, which is what makes a change with no evidence ineligible to
// alert rather than un-gated.
func ChangeInterval(kind ChangeKind, f Freshness) (ObservationInterval, bool) {
	switch kind {
	case ChangeTargetAdded, ChangeTargetRemoved, ChangeAPIAdded,
		ChangeAPIRemoved, ChangeRepositoryAdded, ChangeRepositoryRemoved,
		ChangeMobileAdded, ChangeMobileRemoved,
		ChangeTargetInScope, ChangeTargetOutOfScope,
		ChangeScopeChanged, ChangeSurfaceChanged,
		ChangeScopeReviewChanged:
		return f.ScopeChange, f.ScopeChange.Known()
	case ChangeReputationChanged, ChangeReputationLowered, ChangeReputationRaised,
		ChangeKYCChanged, ChangeKYCRemoved, ChangeKYCRequired,
		ChangeFeeChanged, ChangeFeeReduced, ChangeFeeIncreased,
		ChangeFeeRemoved, ChangeFeeIntroduced,
		ChangePOCChanged, ChangePOCRequired, ChangePOCRemoved,
		ChangeRequirementChanged:
		return f.RequirementChange, f.RequirementChange.Known()
	case ChangeBountyChanged, ChangeBountyRaised, ChangeBountyLowered,
		ChangeCryptoReclassified, ChangeMetadataChanged:
		return f.MetadataChange, f.MetadataChange.Known()
	case ChangeProgramReactivated, ChangeProgramPaused,
		ChangeProgramEnded, ChangeStateChanged:
		// A lifecycle transition is observed directly rather than through a
		// fingerprint, but it is bounded by the same pair of observations and
		// therefore carries the same evidence. Gating it on the metadata interval
		// would be wrong: a rename moves that fingerprint without any lifecycle
		// transition having occurred.
		return f.LifecycleChange, f.LifecycleChange.Known()
	default:
		return ObservationInterval{}, false
	}
}
