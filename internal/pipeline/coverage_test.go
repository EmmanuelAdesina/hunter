package pipeline_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/state"
)

// The regression this file exists for.
//
// A monitoring system's silence has two possible causes: the platform had nothing
// to report, or the sweep stopped seeing the platform. Every other counter in the
// scan is identical in both cases - programs discovered, programs evaluated,
// alerts zero, errors zero, exit success. Before coverage accounting existed, a
// listing sweep that dropped most of the catalogue produced output that was
// indistinguishable from a quiet day, while any change to an unobserved program
// had become permanently undetectable.
//
// These tests pin the accounting that makes the two distinguishable.

// hideFromDiscovery makes the source stop returning a program, while leaving its
// record in state. This is exactly what a dropped listing page looks like.
func hideFromDiscovery(src *fakeSource, id string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	kept := make([]domain.ProgramRef, 0, len(src.refs))
	for _, r := range src.refs {
		if r.ID == id {
			continue
		}
		kept = append(kept, r)
	}
	src.refs = kept
}

// addPrograms grows the source to n additional programs.
func addPrograms(t *testing.T, src *fakeSource, from, to int) {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	for i := from; i < to; i++ {
		id := programID(i)
		src.refs = append(src.refs, domain.ProgramRef{
			Source: "fake", ID: id, Slug: id, Name: "Program " + id,
			URL:     "https://fake.test/programs/" + id,
			Listing: domain.Listing{Status: "LIVE", State: "published", RewardRaw: "$5,000"},
		})
		src.records[id] = defaultRecord(id)
	}
}

func programID(i int) string { return "p" + strconv.Itoa(i) }

// A live program that stops being published is the dangerous case: it is neither
// an error nor a new program, and a change to it can never be detected again.
func TestLiveProgramVanishingIsNamedAndDegrades(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	hideFromDiscovery(src, "beta")

	// Grace is two sweeps: the first miss is a fact, not yet a departure.
	first := scanAt(t, src, dir, accBase.Add(10*time.Minute))
	if len(first.Coverage.Absent) != 0 {
		t.Fatalf("a single missed sweep must not be reported as an absence: %v", first.Coverage.Absent)
	}
	if first.Metrics.Missing != 1 {
		t.Errorf("missing = %d, want 1", first.Metrics.Missing)
	}

	second := scanAt(t, src, dir, accBase.Add(20*time.Minute))
	if len(second.Coverage.Absent) != 1 {
		t.Fatalf("absent = %v, want beta reported after the grace period", second.Coverage.Absent)
	}
	if !containsText(second.Coverage.Absent[0], "beta") {
		t.Errorf("absent entry %q does not name the program", second.Coverage.Absent[0])
	}
	degraded, why := second.Metrics.Degraded()
	if !degraded {
		t.Fatal("a known live program that vanished must degrade the sweep")
	}
	if why == "" {
		t.Error("a degraded sweep must state why")
	}
	if second.Metrics.Absent != 1 {
		t.Errorf("metrics Absent = %d, want 1", second.Metrics.Absent)
	}
}

// Coverage is measured against what the system knew, not against what it
// discovered. A sweep that finds fifty brand-new programs has not lost anything.
func TestNewProgramsDoNotInflateCoverage(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	addPrograms(t, src, 0, 3)

	res := scanAt(t, src, dir, accBase.Add(10*time.Minute))

	if res.Metrics.Expected != 1 {
		t.Fatalf("expected = %d, want 1: newly discovered programs are not obligations",
			res.Metrics.Expected)
	}
	if res.Metrics.CoverageRatio != 1 {
		t.Fatalf("coverage = %v, want 1.0", res.Metrics.CoverageRatio)
	}
	if res.Metrics.New != 3 {
		t.Errorf("new = %d, want 3", res.Metrics.New)
	}
}

// A program that said it was finished, or was unlisted, may legitimately vanish.
// Treating that as a coverage failure would make the alarm cry wolf every time a
// program is retired.
func TestDepartedProgramIsEvictedNotReportedAsAbsent(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	src.mu.Lock()
	rec := src.records["beta"]
	rec.Status = "ENDED"
	src.records["beta"] = rec
	src.mu.Unlock()
	settle(t, src, dir, accBase.Add(10*time.Minute))

	hideFromDiscovery(src, "beta")

	var last = scanAt(t, src, dir, accBase.Add(20*time.Minute))
	for i := 1; i <= 3; i++ {
		last = scanAt(t, src, dir, accBase.Add(time.Duration(20+i*10)*time.Minute))
	}

	if len(last.Coverage.Absent) != 0 {
		t.Errorf("absent = %v, want none: an ended program may depart", last.Coverage.Absent)
	}
	if last.Metrics.Departed != 1 {
		t.Errorf("departed = %d, want 1", last.Metrics.Departed)
	}

	snap, err := state.NewFileStore(dir).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, held := snap.Program("fake:beta"); held {
		t.Error("a departed program is still held; the coverage denominator would grow without bound")
	}
}

// A recovered program returns to full trust immediately, rather than serving out
// a second grace period.
func TestRecoveredProgramIsTrustedAgainAtOnce(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	hideFromDiscovery(src, "beta")
	scanAt(t, src, dir, accBase.Add(10*time.Minute))
	scanAt(t, src, dir, accBase.Add(20*time.Minute))
	if got := scanAt(t, src, dir, accBase.Add(30*time.Minute)); len(got.Coverage.Absent) != 1 {
		t.Fatalf("beta was not reported absent: %v", got.Coverage.Absent)
	}

	src.mu.Lock()
	src.refs = append(src.refs, domain.ProgramRef{
		Source: "fake", ID: "beta", Slug: "beta", Name: "Program beta",
		URL:     "https://fake.test/programs/beta",
		Listing: domain.Listing{Status: "LIVE", State: "published", RewardRaw: "$5,000"},
	})
	src.mu.Unlock()

	back := scanAt(t, src, dir, accBase.Add(40*time.Minute))
	if len(back.Coverage.Absent) != 0 {
		t.Errorf("absent = %v, want none once the program is seen again", back.Coverage.Absent)
	}
	if back.Metrics.Missing != 0 {
		t.Errorf("missing = %d, want 0", back.Metrics.Missing)
	}
	if back.Metrics.CoverageRatio != 1 {
		t.Errorf("coverage = %v, want 1.0 immediately on recovery", back.Metrics.CoverageRatio)
	}
}

// A first run has nothing to expect. It is not a coverage failure, and it must
// not print a misleading zero percent.
func TestFirstRunIsNotACoverageFailure(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()

	res := scanAt(t, src, dir, accBase)
	if res.Metrics.CoverageRatio != -1 {
		t.Errorf("coverage = %v, want -1 on a first run", res.Metrics.CoverageRatio)
	}
	if res.Metrics.Expected != 0 {
		t.Errorf("expected = %d, want 0 on a first run", res.Metrics.Expected)
	}
	if degraded, _ := res.Metrics.Degraded(); degraded {
		t.Error("a first run must not be degraded; there was nothing to expect")
	}
}

// Partial loss below the floor degrades even when no single program has been
// absent long enough to be named. That is the rate-limited-pagination case: the
// programs come back eventually, but this sweep saw a fraction of the platform,
// so a change on an unobserved program was undetectable for this cycle.
func TestPartialLossBelowTheFloorDegrades(t *testing.T) {
	src := newFakeSource()
	addPrograms(t, src, 0, 40)
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	for i := 0; i < 40; i += 2 {
		hideFromDiscovery(src, programID(i))
	}
	scanAt(t, src, dir, accBase.Add(10*time.Minute))
	res := scanAt(t, src, dir, accBase.Add(20*time.Minute))

	if res.Metrics.CoverageRatio >= 0.9 {
		t.Fatalf("coverage = %v, expected it below the 0.9 floor", res.Metrics.CoverageRatio)
	}
	degraded, why := res.Metrics.Degraded()
	if !degraded {
		t.Fatal("coverage below the floor must degrade the sweep")
	}
	if why == "" {
		t.Error("a degraded sweep must state why")
	}
}

// The absence counter saturates, or a permanently absent program would rewrite
// state on every sweep and turn the repository into a commit log of nothing.
func TestAbsenceCounterSaturates(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	hideFromDiscovery(src, "beta")
	for i := 0; i < 5; i++ {
		scanAt(t, src, dir, accBase.Add(time.Duration(10+i*10)*time.Minute))
	}

	snap, err := state.NewFileStore(dir).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p, held := snap.Program("fake:beta")
	if !held {
		t.Skip("beta was evicted; the counter no longer applies")
	}
	if p.AbsentScans > 4 {
		t.Fatalf("AbsentScans = %d, want it saturated near the cap", p.AbsentScans)
	}

	// Further sweeps must not move the counter. It is deliberately not the whole
	// digest that is asserted here: DetailsFetchedAt is part of the digest by
	// design, so a still-polled program legitimately changes it every sweep.
	for i := 0; i < 2; i++ {
		scanAt(t, src, dir, accBase.Add(time.Duration(300+i*10)*time.Minute))
		snap, err = state.NewFileStore(dir).Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		again, held := snap.Program("fake:beta")
		if !held {
			t.Skip("beta was evicted")
		}
		if again.AbsentScans != p.AbsentScans {
			t.Fatalf("AbsentScans moved from %d to %d after further sweeps; "+
				"a settled absence must stop changing state", p.AbsentScans, again.AbsentScans)
		}
	}
}

// AbsentScans is a relationship between a program and a sweep, not a property of
// the program. Folding it into a fingerprint would mark every program changed on
// the sweep that missed it.
func TestAbsentScansIsExcludedFromFingerprints(t *testing.T) {
	p := domain.Program{ID: "p", Source: "fake", Slug: "p", Name: "P", State: domain.StateLive}
	p.Finalize()
	before := p.MetadataFingerprint
	p.AbsentScans = 3
	p.Finalize()
	if p.MetadataFingerprint != before {
		t.Fatal("AbsentScans must not participate in any fingerprint")
	}
}

func containsText(haystack, want string) bool {
	for i := 0; i+len(want) <= len(haystack); i++ {
		if haystack[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
