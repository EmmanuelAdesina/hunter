package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

// An interval built from two observations must bound the event between them and
// nowhere else. This is the whole contract: the system knows a change happened
// between two scans and does not know when.
func TestObservationIntervalBoundsBetweenObservations(t *testing.T) {
	iv := NewObservationInterval(at("2026-10-04T14:00:00Z"), at("2026-10-04T14:14:00Z"))

	if !iv.Known() {
		t.Fatal("an interval bounded by two observations must be known")
	}
	if got, want := iv.Width(), 14*time.Minute; got != want {
		t.Fatalf("width = %s, want %s", got, want)
	}
	if got, want := iv.Basis, BasisBetweenObservations; got != want {
		t.Fatalf("basis = %q, want %q", got, want)
	}
}

// The two ends of the interval are different numbers. Collapsing them to one is
// the defect this type exists to prevent, so both must stay addressable.
func TestObservationIntervalAgesAreARangeNotAPoint(t *testing.T) {
	now := at("2026-10-04T14:20:00Z")
	iv := NewObservationInterval(at("2026-10-04T14:00:00Z"), at("2026-10-04T14:14:00Z"))

	if got, want := iv.NewestAge(now), 6*time.Minute; got != want {
		t.Fatalf("newest age = %s, want %s", got, want)
	}
	if got, want := iv.OldestAge(now), 20*time.Minute; got != want {
		t.Fatalf("oldest age = %s, want %s", got, want)
	}
	if iv.NewestAge(now) == iv.OldestAge(now) {
		t.Fatal("a fourteen-minute observation interval must not report a single age")
	}
}

// An unknown interval must stay unknown through every accessor. Rendering an
// unknown interval as zero, or as "just now", would assert a recency the system
// does not have.
func TestUnknownIntervalNeverReportsARecency(t *testing.T) {
	now := at("2026-10-04T14:20:00Z")
	var iv ObservationInterval

	if iv.Known() {
		t.Fatal("the zero interval must not report as known")
	}
	if !iv.Zero() {
		t.Fatal("the zero interval must report as zero")
	}
	if got := iv.NewestAge(now); got != 0 {
		t.Fatalf("newest age = %s, want 0", got)
	}
	if got := iv.OldestAge(now); got != 0 {
		t.Fatalf("oldest age = %s, want 0", got)
	}
	if got := iv.Humanize(now); got != "unknown" {
		t.Fatalf("Humanize = %q, want %q", got, "unknown")
	}
	if iv.DefinitelyWithin(now, 72*time.Hour) {
		t.Fatal("an unknown interval must not be definitely within any window")
	}
	if iv.PossiblyWithin(now, 72*time.Hour) {
		t.Fatal("an unknown interval must not be possibly within any window")
	}
}

// A half-built interval is not usable. Only one bound would let a renderer print
// a single number and imply it was exact.
func TestHalfBoundedIntervalIsUnknown(t *testing.T) {
	if NewObservationInterval(time.Time{}, at("2026-10-04T14:14:00Z")).Known() {
		t.Fatal("an interval with no lower bound must not report as known")
	}
	if NewObservationInterval(at("2026-10-04T14:00:00Z"), time.Time{}).Known() {
		t.Fatal("an interval with no upper bound must not report as known")
	}
}

// Clock skew between a stored record and the running process must not produce an
// inverted interval, which would render as a negative width.
func TestInvertedIntervalIsRejected(t *testing.T) {
	iv := NewObservationInterval(at("2026-10-04T14:14:00Z"), at("2026-10-04T14:00:00Z"))
	if iv.Known() {
		t.Fatal("an inverted interval must be rejected rather than stored")
	}
}

// A source whose update marker has day resolution yields an interval hours wide.
// That width is information: the platform does not know precisely either.
func TestSourceMarkerIntervalSpansTheMarkerDay(t *testing.T) {
	marker := at("2026-10-04T00:00:00Z")
	observed := at("2026-10-04T14:20:00Z")

	iv := NewObservationIntervalFromSourceMarker(marker, observed)
	if !iv.Known() {
		t.Fatal("a marker-bounded interval must be known")
	}
	if got, want := iv.Basis, BasisSourceMarker; got != want {
		t.Fatalf("basis = %q, want %q", got, want)
	}
	if got, want := iv.Width(), 14*time.Hour+20*time.Minute; got != want {
		t.Fatalf("width = %s, want %s", got, want)
	}
	if NewObservationIntervalFromSourceMarker(time.Time{}, observed).Known() {
		t.Fatal("a missing marker must not produce an interval")
	}
}

// Rendering states the bound, not a fabricated instant.
func TestIntervalHumanizeShowsTheRange(t *testing.T) {
	now := at("2026-10-04T14:20:00Z")

	wide := NewObservationInterval(at("2026-10-04T14:00:00Z"), at("2026-10-04T14:14:00Z"))
	if got, want := wide.Humanize(now), "within the last 6m-20m"; got != want {
		t.Fatalf("Humanize = %q, want %q", got, want)
	}

	tight := NewObservationInterval(at("2026-10-04T14:19:30Z"), at("2026-10-04T14:20:00Z"))
	if got, want := tight.Humanize(now), "within the last just now"; got != want {
		t.Fatalf("Humanize = %q, want %q", got, want)
	}
}

// Alert gating is deliberately asymmetric: a change that might still be fresh is
// treated as fresh. Missing a real opportunity is worse than one stale email, and
// the rendered range is what discloses the ambiguity.
func TestPossiblyWithinIsTheAlertingGate(t *testing.T) {
	now := at("2026-10-04T14:20:00Z")

	// The observation interval straddles a six-hour window: the change may have
	// happened 10h ago (stale) or 4h ago (fresh). The permissive gate must let
	// it through, because the researcher cannot be told which, and the strict
	// gate must not claim certainty.
	straddleWindow := 6 * time.Hour
	straddle := NewObservationInterval(at("2026-10-04T04:20:00Z"), at("2026-10-04T10:20:00Z"))
	if straddle.OldestAge(now) != 10*time.Hour {
		t.Fatalf("oldest age = %s, want 10h", straddle.OldestAge(now))
	}
	if straddle.NewestAge(now) != 4*time.Hour {
		t.Fatalf("newest age = %s, want 4h", straddle.NewestAge(now))
	}
	if !straddle.PossiblyWithin(now, straddleWindow) {
		t.Fatal("a change that may still be inside the window must alert")
	}
	if straddle.DefinitelyWithin(now, straddleWindow) {
		t.Fatal("a straddling change must not claim to be definitely inside the window")
	}

	// Wholly inside a wide window: both readings qualify.
	wideWindow := 72 * time.Hour
	if !straddle.PossiblyWithin(now, wideWindow) {
		t.Fatal("a change wholly inside the window must alert")
	}
	if !straddle.DefinitelyWithin(now, wideWindow) {
		t.Fatal("a change wholly inside the window must be definite")
	}

	// Wholly outside: no admissible placement is fresh.
	stale := NewObservationInterval(at("2026-09-30T04:20:00Z"), at("2026-09-30T10:20:00Z"))
	if stale.PossiblyWithin(now, wideWindow) {
		t.Fatal("a wholly stale change must not alert")
	}
	if stale.DefinitelyWithin(now, wideWindow) {
		t.Fatal("a wholly stale change must not be definite")
	}
}

// A zero or negative window disables its trigger rather than widening it to
// infinity, which would turn a missing configuration into a firehose.
func TestNonPositiveWindowNeverMatches(t *testing.T) {
	now := at("2026-10-04T14:20:00Z")
	iv := NewObservationInterval(at("2026-10-04T14:00:00Z"), at("2026-10-04T14:14:00Z"))

	if iv.PossiblyWithin(now, 0) {
		t.Fatal("a zero window must never match")
	}
	if iv.DefinitelyWithin(now, -time.Hour) {
		t.Fatal("a negative window must never match")
	}
}

// An unknown interval serializes as null rather than as a pair of year-1
// timestamps, which would read as a real date to anything consuming the state.
func TestUnknownIntervalMarshalsAsNull(t *testing.T) {
	data, err := json.Marshal(ObservationInterval{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(data) != "null" {
		t.Fatalf("unknown interval marshalled as %s, want null", data)
	}
}

// State files round-trip. The interval must survive a write and a read without
// losing its bounds or its basis.
func TestObservationIntervalRoundTrips(t *testing.T) {
	original := ObservationInterval{
		NotBefore: at("2026-10-04T14:00:00Z"),
		NotAfter:  at("2026-10-04T14:14:00Z"),
		Basis:     BasisBetweenObservations,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ObservationInterval
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != original {
		t.Fatalf("round trip changed the interval:\n got %+v\nwant %+v", back, original)
	}

	// A null must decode to the zero value rather than failing, so a state file
	// written before the field existed loads cleanly.
	if err := json.Unmarshal([]byte("null"), &back); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if back.Known() {
		t.Fatal("a null interval must decode as unknown")
	}
}

// Program fingerprints must not include the change intervals. The intervals
// describe when a fingerprint moved, so folding them in would make every program
// look changed on the scan after a change is recorded.
func TestChangeIntervalsAreExcludedFromFingerprints(t *testing.T) {
	p := Program{Name: "Example", Slug: "example", Source: "test", State: StateLive}
	p.Finalize()
	before := p.MetadataFingerprint

	p.ScopeChanged = NewObservationInterval(at("2026-10-04T14:00:00Z"), at("2026-10-04T14:14:00Z"))
	p.Finalize()

	if p.MetadataFingerprint != before {
		t.Fatal("recording a change interval must not alter any fingerprint")
	}
}
