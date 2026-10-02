// Package domain contains the canonical, source-agnostic program model.
//
// Nothing in this package may import a source adapter, a notifier, or a
// storage backend. The domain is the stable centre of the system: adapters
// translate into it, and policy, diffing, scoring, and alerting read out of it.
package domain

import (
	"encoding/json"
	"fmt"
)

// Tri is a three-valued boolean used for every access-critical fact.
//
// The distinction it encodes is the single most important safety property in
// this system: an unknown fact must never silently collapse into a known fact.
// A parser that breaks, a field that disappears from a source page, or a value
// we deliberately decline to interpret all resolve to TriUnknown. Only
// explicit observation may produce TriYes or TriNo.
type Tri uint8

const (
	// TriUnknown means the fact could not be determined from available data.
	// Policy must treat this as a rejection unless the profile explicitly
	// opts into accepting unknowns.
	TriUnknown Tri = iota
	// TriYes means the fact was positively observed.
	TriYes
	// TriNo means the fact was positively observed to be false.
	TriNo
)

var triNames = [...]string{"unknown", "yes", "no"}

// String returns a stable lowercase name. The mapping is deliberately the
// inverse of intuition (unknown first) so that the zero value has a name.
func (t Tri) String() string {
	if int(t) >= len(triNames) {
		return fmt.Sprintf("invalid(%d)", uint8(t))
	}
	return triNames[t]
}

// Known reports whether the fact was positively observed either way.
func (t Tri) Known() bool { return t == TriYes || t == TriNo }

// Bool returns the boolean value and whether it was known.
func (t Tri) Bool() (value bool, known bool) {
	switch t {
	case TriYes:
		return true, true
	case TriNo:
		return false, true
	default:
		return false, false
	}
}

// Yes returns true only when the fact was positively observed as true.
// It is the safe accessor: TriUnknown never satisfies it.
func (t Tri) Yes() bool { return t == TriYes }

// No returns true only when the fact was positively observed as false.
func (t Tri) No() bool { return t == TriNo }

// TriOf builds a Tri from a known boolean.
func TriOf(b bool) Tri {
	if b {
		return TriYes
	}
	return TriNo
}

// TriFromKnown builds a Tri from a boolean that may not be known.
// ok=false yields TriUnknown, never a fabricated value.
func TriFromKnown(value, ok bool) Tri {
	if !ok {
		return TriUnknown
	}
	return TriOf(value)
}

// ParseTri reads a tri-state from configuration text.
func ParseTri(s string) (Tri, error) {
	switch s {
	case "yes", "true", "required", "always":
		return TriYes, nil
	case "no", "false", "not_required", "never":
		return TriNo, nil
	case "unknown", "any", "unspecified":
		return TriUnknown, nil
	default:
		return TriUnknown, fmt.Errorf("invalid tri-state %q: want yes|no|unknown", s)
	}
}

func (t Tri) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }

func (t *Tri) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseTri(s)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

func (t Tri) MarshalYAML() (any, error) { return t.String(), nil }

func (t *Tri) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := ParseTri(s)
	if err != nil {
		return err
	}
	*t = v
	return nil
}
