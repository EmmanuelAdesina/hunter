package domain

import (
	"sort"
	"strconv"
	"strings"
)

// Direction states which way a field moved.
//
// Direction is what separates an event worth interrupting for from the same
// event with the opposite sign. REPUTATION_LOWERED and REPUTATION_RAISED alter
// one number, and only one of them makes a program reachable for this
// researcher. Recording the direction at detection time means no downstream
// consumer has to re-derive it from the two string values, and no consumer can
// disagree about it.
type Direction string

const (
	// DirectionUnknown means the change did not move in an interpretable
	// direction, such as a value becoming unknown rather than a number changing.
	DirectionUnknown Direction = "unknown"

	// DirectionImproved means the change made the program more reachable, more
	// testable, or better compensated.
	DirectionImproved Direction = "improved_access"

	// DirectionDegraded means the change closed access, removed testable
	// surface, or lowered compensation.
	DirectionDegraded Direction = "degraded_access"

	// DirectionNeutral means the change is real but does not favour either side.
	DirectionNeutral Direction = "neutral"
)

// Delta is one atomic, directional change to a single field.
//
// A Delta is the unit of evidence. It names one field, carries the value on both
// sides, states which way it moved, and — where the field is numeric — how far.
// Nothing is inferred and nothing is fused: "access improved" is not a Delta,
// because it is a conclusion about several Deltas and conclusions belong to the
// window that contains them, not to the evidence inside it.
//
// Numeric magnitude is deliberately optional. "API added" is a delta with two
// asset names and no number, and pretending otherwise would invent precision.
type Delta struct {
	// Field names what changed, e.g. "reputation" or "submission_fee".
	Field string `json:"field"`

	// Kind is the specific semantic event, e.g. ChangeReputationLowered. It is
	// what window identity and trigger selection key on.
	Kind ChangeKind `json:"kind"`

	// Before and After are human-readable renderings of the two values. They are
	// strings because the fields they describe are heterogeneous, and because
	// they are written to be read in a notification.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`

	// Direction states which way the field moved.
	Direction Direction `json:"direction"`

	// Magnitude is the absolute size of a numeric change. Zero when the change
	// is not numeric or the size is not meaningful.
	Magnitude float64 `json:"magnitude,omitempty"`

	// Assets lists the specific identifiers involved, for asset changes.
	Assets []string `json:"assets,omitempty"`

	// Basis records the evidence the delta was derived from, so that a reader can
	// tell a read from a page field from one inferred from prose.
	Basis string `json:"basis,omitempty"`
}

// Improved reports whether the delta moved in the researcher's favour.
func (d Delta) Improved() bool { return d.Direction == DirectionImproved }

// Degraded reports whether the delta moved against the researcher.
func (d Delta) Degraded() bool { return d.Direction == DirectionDegraded }

// Describe renders one alert-ready line.
func (d Delta) Describe() string {
	var b strings.Builder
	switch d.Direction {
	case DirectionImproved:
		b.WriteString("+ ")
	case DirectionDegraded:
		b.WriteString("- ")
	default:
		b.WriteString("~ ")
	}
	b.WriteString(string(d.Kind))
	if d.Before != "" && d.After != "" {
		b.WriteString(": ")
		b.WriteString(d.Before)
		b.WriteString(" -> ")
		b.WriteString(d.After)
	} else if d.After != "" {
		b.WriteString(": ")
		b.WriteString(d.After)
	}
	if len(d.Assets) > 0 {
		shown := d.Assets
		if len(shown) > 6 {
			shown = append(append([]string{}, shown[:6]...), "(+"+strconv.Itoa(len(d.Assets)-6)+" more)")
		}
		b.WriteString(" [")
		b.WriteString(strings.Join(shown, ", "))
		b.WriteString("]")
	}
	return b.String()
}

// Deltas is an ordered collection of atomic changes.
type Deltas []Delta

// Improved returns the deltas that moved in the researcher's favour.
func (ds Deltas) Improved() Deltas { return ds.filter(DirectionImproved) }

// Degraded returns the deltas that moved against the researcher.
func (ds Deltas) Degraded() Deltas { return ds.filter(DirectionDegraded) }

func (ds Deltas) filter(dir Direction) Deltas {
	out := make(Deltas, 0, len(ds))
	for _, d := range ds {
		if d.Direction == dir {
			out = append(out, d)
		}
	}
	return out
}

// Kinds returns the distinct kinds present, sorted for stable output.
func (ds Deltas) Kinds() []string {
	out := make([]string, 0, len(ds))
	seen := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		if _, dup := seen[string(d.Kind)]; dup {
			continue
		}
		seen[string(d.Kind)] = struct{}{}
		out = append(out, string(d.Kind))
	}
	sort.Strings(out)
	return out
}

// Empty reports whether the set holds no deltas.
func (ds Deltas) Empty() bool { return len(ds) == 0 }

// Identity renders a stable string over the set, used as window event identity.
//
// It covers every field that distinguishes one evidence bundle from another. It
// deliberately excludes anything time-derived, because two scans observing the
// same transition must produce the same identity or the same opportunity would
// open twice.
func (ds Deltas) Identity() string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		parts = append(parts, strings.Join([]string{
			string(d.Kind), d.Field, d.Before, d.After,
			string(d.Direction), formatMagnitude(d.Magnitude),
			strings.Join(d.Assets, "+"),
		}, "\x1f"))
	}
	// Sorted so that detection order, which depends on map iteration inside the
	// diff, cannot change the identity.
	sort.Strings(parts)
	return strings.Join(parts, "\x1e")
}

func formatMagnitude(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
