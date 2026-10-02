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
	ChangeAPIAdded           ChangeKind = "API_ADDED"
	ChangeAPIRemoved         ChangeKind = "API_REMOVED"
	ChangeRepositoryAdded    ChangeKind = "REPOSITORY_ADDED"
	ChangeRepositoryRemoved  ChangeKind = "REPOSITORY_REMOVED"
	ChangeMobileAdded        ChangeKind = "MOBILE_ADDED"
	ChangeRequirementChanged ChangeKind = "REQUIREMENT_CHANGED"
	ChangeKYCChanged         ChangeKind = "KYC_CHANGED"
	ChangeReputationChanged  ChangeKind = "REPUTATION_CHANGED"
	ChangeFeeChanged         ChangeKind = "SUBMISSION_FEE_CHANGED"
	ChangePOCChanged         ChangeKind = "POC_CHANGED"
	ChangeBountyChanged      ChangeKind = "BOUNTY_CHANGED"
	ChangeScopeReviewChanged ChangeKind = "SCOPE_REVIEW_CHANGED"
	ChangeMetadataChanged    ChangeKind = "METADATA_CHANGED"
	ChangeCryptoReclassified ChangeKind = "CRYPTO_RECLASSIFIED"
	ChangeSurfaceChanged     ChangeKind = "SURFACE_CHANGED"
	ChangeSubmissionsChanged ChangeKind = "SUBMISSIONS_CHANGED"
)

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

	// Detail adds context for decisions that are not obvious from the fields.
	Detail string `json:"detail,omitempty"`
}

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
