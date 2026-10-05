package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

// IntervalBasis explains how an observation interval was bounded.
//
// The basis travels with every interval so that a reader can tell a measured
// bound from a derived one. An interval derived from a source's own
// day-resolution update marker is a weaker claim than one derived from two
// observations this system actually made, and presenting them identically would
// overstate the second.
type IntervalBasis string

const (
	// BasisUnknown means the event could not be bounded at all. It is a real
	// state, not a placeholder: an unbounded event must never be reported as
	// recent, and must never open an opportunity window.
	BasisUnknown IntervalBasis = "unknown"

	// BasisBetweenObservations means the event happened somewhere between two
	// observations this system actually made. This is the strongest bound
	// available and the normal case.
	BasisBetweenObservations IntervalBasis = "observed_between_observations"

	// BasisFirstObservation means the event is the transition from unobserved to
	// observed. The lower bound is the moment this system first saw the program,
	// so the interval is bounded above by the current observation and left open
	// below by the program's own history.
	BasisFirstObservation IntervalBasis = "first_observation"

	// BasisSourceMarker means the event is bounded by the source's own
	// last-modified marker. On a platform whose marker has day resolution this
	// yields an interval hours wide, which is exactly the width that should be
	// shown rather than collapsed to a point.
	BasisSourceMarker IntervalBasis = "source_last_modified"
)

// ObservationInterval bounds when an event may have occurred.
//
// # Why this exists
//
// Hunter compares two observations. When they differ, the system knows a change
// happened between them and it does NOT know when. Storing a single timestamp
// would assert a precision the system never had: "changed at 14:03:17" is a
// claim, and the only evidence for it is that two scans were minutes apart.
//
// The interval is the honest form of that evidence. NotBefore is the last
// observation that did not show the change; NotAfter is the first that did.
// Every age derived from it is a range, and every renderer is required to show
// the range.
//
// This is the same discipline the rest of the model already follows: Tri keeps
// "the source did not say" distinct from "the source said no", and
// Program.Age returns an AgeBasis so an estimate can explain itself. An interval
// is the temporal expression of that rule.
type ObservationInterval struct {
	// NotBefore is the earliest instant the event may have occurred.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the latest instant the event may have occurred.
	NotAfter time.Time `json:"not_after"`

	// Basis records how the bounds were established.
	Basis IntervalBasis `json:"basis"`
}

// NewObservationInterval bounds an event between two observations.
func NewObservationInterval(notBefore, notAfter time.Time) ObservationInterval {
	iv := ObservationInterval{Basis: BasisBetweenObservations}
	if notBefore.IsZero() || notAfter.IsZero() {
		return ObservationInterval{}
	}
	// A clock that runs backwards, or a scan whose stored record was written
	// after the current one, must not produce an inverted interval. An inverted
	// interval would render as a negative width and a negative age, which reads
	// as a bug rather than as an untrustworthy bound.
	if notAfter.Before(notBefore) {
		return ObservationInterval{}
	}
	iv.NotBefore = notBefore.UTC()
	iv.NotAfter = notAfter.UTC()
	return iv
}

// NewObservationIntervalFromSourceMarker bounds an event using the source's own
// last-modified marker.
//
// The lower bound is the marker's day-resolution start, so an event the source
// dated "today" produces an interval hours wide rather than a false point. That
// width is information: it tells the reader that the platform itself does not
// know precisely when this happened either.
func NewObservationIntervalFromSourceMarker(marker time.Time, observedAt time.Time) ObservationInterval {
	if marker.IsZero() || observedAt.IsZero() {
		return ObservationInterval{}
	}
	start := time.Date(marker.Year(), marker.Month(), marker.Day(), 0, 0, 0, 0, time.UTC)
	return ObservationInterval{
		NotBefore: start,
		NotAfter:  observedAt.UTC(),
		Basis:     BasisSourceMarker,
	}
}

// FirstObservationInterval bounds the moment a program entered the system.
//
// The lower bound is left at the observed moment because nothing before it was
// observed at all, which makes the interval's Basis the thing that carries the
// caveat rather than its width.
func FirstObservationInterval(observedAt time.Time) ObservationInterval {
	if observedAt.IsZero() {
		return ObservationInterval{}
	}
	t := observedAt.UTC()
	return ObservationInterval{NotBefore: t, NotAfter: t, Basis: BasisFirstObservation}
}

// Known reports whether the interval carries usable bounds.
//
// An interval is known only when both bounds are present. A half-bounded
// interval would let a renderer print one number and imply it was exact, which
// is the failure this type exists to prevent.
func (iv ObservationInterval) Known() bool {
	return !iv.NotBefore.IsZero() && !iv.NotAfter.IsZero()
}

// Zero reports whether the interval is entirely unset.
func (iv ObservationInterval) Zero() bool { return iv == ObservationInterval{} }

// Width is how much slack the observation left.
//
// A zero width means the two bounding observations coincided, which in practice
// means the width is not informative rather than that the event was timed to
// the nanosecond.
func (iv ObservationInterval) Width() time.Duration {
	if !iv.Known() {
		return 0
	}
	return iv.NotAfter.Sub(iv.NotBefore)
}

// NewestAge is the smallest age the event could have.
//
// This is the optimistic bound: the event may be as young as this.
func (iv ObservationInterval) NewestAge(now time.Time) time.Duration {
	if !iv.Known() {
		return 0
	}
	return nonNegative(now.Sub(iv.NotAfter))
}

// OldestAge is the largest age the event could have.
//
// This is the conservative bound: the event may be as old as this.
func (iv ObservationInterval) OldestAge(now time.Time) time.Duration {
	if !iv.Known() {
		return 0
	}
	return nonNegative(now.Sub(iv.NotBefore))
}

// DefinitelyWithin reports that every admissible placement of the event is no
// older than window.
//
// That requires the OLDEST admissible placement - NotBefore - to be inside the
// window, so this is the strict reading: the opportunity is certainly still
// fresh no matter when in the interval the change actually happened.
func (iv ObservationInterval) DefinitelyWithin(now time.Time, window time.Duration) bool {
	if !iv.Known() || window <= 0 {
		return false
	}
	return iv.OldestAge(now) <= window
}

// PossiblyWithin reports that SOME admissible placement of the event is no older
// than window.
//
// That requires only the NEWEST admissible placement - NotAfter - to be inside
// the window, so this is the permissive reading: the opportunity may still be
// fresh even though the exact moment is unknown.
//
// Alert gating uses this rather than DefinitelyWithin. The asymmetry is
// deliberate and it is the whole point of the type. The cost of alerting on a
// change that turns out to be slightly stale is one unnecessary email; the cost
// of gating on DefinitelyWithin is a genuinely fresh opportunity being lost
// every time a scan interval straddles the window boundary - which, at a
// five-minute cadence against a 72-hour window, is a narrow case for the alert
// and a permanent blind spot for the researcher. The rendered age range is what
// discloses the ambiguity to the reader, not the gate.
func (iv ObservationInterval) PossiblyWithin(now time.Time, window time.Duration) bool {
	if !iv.Known() || window <= 0 {
		return false
	}
	return iv.NewestAge(now) <= window
}

// Humanize renders the interval as a bounded range, for display.
//
// The two numbers are the youngest and oldest ages the event could have. When
// the interval is narrower than a displayable unit they collapse to one number,
// which is a rounding of a measured bound rather than an invented precision:
// below the resolution of the display, the bound and the point are the same
// claim.
//
// An unknown interval renders as such. It never renders as zero and never
// renders as "just now", because both would assert a recency the system does
// not have.
func (iv ObservationInterval) Humanize(now time.Time) string {
	if !iv.Known() {
		return "unknown"
	}
	newest := HumanizeQuantity(iv.NewestAge(now))
	oldest := HumanizeQuantity(iv.OldestAge(now))
	if newest == oldest {
		return "within the last " + newest
	}
	return "within the last " + newest + "-" + oldest
}

// String renders the interval for logs.
func (iv ObservationInterval) String() string {
	if !iv.Known() {
		return "interval(unknown)"
	}
	return fmt.Sprintf("interval[%s..%s basis=%s]",
		iv.NotBefore.Format(time.RFC3339),
		iv.NotAfter.Format(time.RFC3339),
		iv.Basis)
}

// MarshalJSON emits null for an unknown interval.
//
// The alternative is a pair of year-1 timestamps in every state file, which is
// both noise in a reviewable diff and a value that reads as a real date to
// anything consuming the state. A nullable interval states the same fact
// honestly.
func (iv ObservationInterval) MarshalJSON() ([]byte, error) {
	if !iv.Known() {
		return []byte("null"), nil
	}
	type alias ObservationInterval
	return json.Marshal(alias(iv))
}

// UnmarshalJSON accepts both a populated interval and an explicit null, so that
// a state file written by this build round-trips through a build that does not
// know the field at all.
func (iv *ObservationInterval) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*iv = ObservationInterval{}
		return nil
	}
	type alias ObservationInterval
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*iv = ObservationInterval(a)
	return nil
}

// nonNegative clamps a duration to zero.
//
// A negative age means the bounding timestamp is in the future relative to the
// supplied clock, which happens with clock skew between a stored record and the
// running process. Clamping keeps the age usable while the Basis and the raw
// bounds still record what was actually observed.
func nonNegative(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}
