package pipeline_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/obs"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
)

// The regression this file exists for:
//
// A change interval used to be computed per scan from the current comparison and
// never stored. It therefore existed only for the one scan that detected the
// change and read as unknown on every scan afterwards. The alert that reported a
// fresh opportunity was, one scan later, unable to say when the opportunity
// opened - so the freshness component fell back to program age and a five-year
// old program scored as though nothing had happened to it.
//
// Every test here pins one link in that chain.

// scanAt runs one scan with a movable clock and a detail page that is always
// re-read.
//
// Forcing the detail read matters: the two-tier read is what makes a scan cheap,
// but it also means a change is detected at the first detail read AFTER it
// happened, not at the moment it happened. Without forcing it, these tests would
// be measuring the refresh interval rather than the interval bookkeeping.
func scanAt(t *testing.T, src domain.ProgramSource, dir string, now time.Time) pipeline.Result {
	t.Helper()
	clock := now
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Now = func() time.Time { return clock }
		c.Profile.Scan.DetailsRefreshInterval = 1
	})
	if err != nil {
		t.Fatalf("Scan at %s: %v", now, now)
	}
	return res
}

// scanListingOnly runs one scan that never reads a detail page, so the change
// bookkeeping is exercised on the cheap path.
func scanListingOnly(t *testing.T, src domain.ProgramSource, dir string, now time.Time) pipeline.Result {
	t.Helper()
	clock := now
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Now = func() time.Time { return clock }
		c.FetchDetails = false
	})
	if err != nil {
		t.Fatalf("listing-only scan at %s: %v", now, err)
	}
	return res
}

func loadProgram(t *testing.T, dir, id string) domain.Program {
	t.Helper()
	snap, err := state.NewFileStore(dir).Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	p, ok := snap.Program("fake:" + id)
	if !ok {
		t.Fatalf("program %q not found in state", id)
	}
	return p
}

// addAPIScope gives a program a new API asset, which moves the scope fingerprint.
func addAPIScope(src *fakeSource, id string, target string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	rec.Scopes = append(rec.Scopes, domain.RawScope{Title: "API", Target: target})
	src.records[id] = rec
}

// The interval must survive the scans that follow the one that detected the
// change, with its original bounds intact.
func TestChangeIntervalSurvivesSubsequentScans(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	// The scope moves.
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	changed := base.Add(9 * time.Minute)
	scanAt(t, src, dir, changed)

	atChange := loadProgram(t, dir, "alpha")
	if !atChange.ScopeChanged.Known() {
		t.Fatal("the scan that detected a scope change must record a known interval")
	}
	if !atChange.ScopeChanged.NotBefore.Equal(base) {
		t.Errorf("interval lower bound = %s, want the preceding observation %s",
			atChange.ScopeChanged.NotBefore, base)
	}
	if !atChange.ScopeChanged.NotAfter.Equal(changed) {
		t.Errorf("interval upper bound = %s, want %s",
			atChange.ScopeChanged.NotAfter, changed)
	}

	// Several later scans see nothing change. The interval must be carried
	// forward untouched, not recomputed and not discarded.
	for i, later := range []time.Duration{
		14 * time.Minute,
		40 * time.Minute,
		3 * time.Hour,
		26 * time.Hour,
	} {
		at := changed.Add(later)
		scanAt(t, src, dir, at)

		p := loadProgram(t, dir, "alpha")
		if !p.ScopeChanged.Known() {
			t.Fatalf("scan %d (%s after the change): the scope interval was discarded", i, later)
		}
		if !p.ScopeChanged.NotBefore.Equal(base) {
			t.Errorf("scan %d: lower bound drifted to %s, want %s",
				i, p.ScopeChanged.NotBefore, base)
		}
		if !p.ScopeChanged.NotAfter.Equal(changed) {
			t.Errorf("scan %d: upper bound drifted to %s, want %s",
				i, p.ScopeChanged.NotAfter, changed)
		}
	}
}

// The interval is what the freshness component reads. A week after a change, a
// five-year-old program whose API was added must still score on the change, not
// on its launch date.
func TestFreshnessUsesTheCarriedIntervalNotProgramAge(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	// Make the program genuinely old.
	src.mu.Lock()
	rec := src.records["alpha"]
	rec.RawDates.Start = "01 Jan 2021"
	src.records["alpha"] = rec
	src.mu.Unlock()
	scanAt(t, src, dir, base.Add(time.Minute))

	changed := base.Add(9 * time.Minute)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, changed)

	// A week later the detail page is re-read and nothing has changed since.
	later := changed.Add(7 * 24 * time.Hour)
	res := scanAt(t, src, dir, later)

	p := loadProgram(t, dir, "alpha")
	if !p.ScopeChanged.Known() {
		t.Fatal("the scope interval must still be known a week later")
	}
	age, basis := p.Age(later)
	if age < 5*365*24*time.Hour || basis != domain.AgeFromLaunch {
		t.Fatalf("program age = %s (%s), want over five years from the launch date", age, basis)
	}

	var found bool
	for _, e := range res.Programs {
		if e.Program.ID != "fake:alpha" {
			continue
		}
		found = true

		comp, ok := e.Triage.Component("freshness")
		if !ok {
			t.Fatal("the freshness component must be present")
		}
		// Program age alone would score near zero. The change is a week old,
		// inside the default freshness window, so the component must reflect it.
		if comp.Value < 90 {
			t.Fatalf("freshness = %d (%s), want a high score from the carried interval",
				comp.Value, comp.Basis)
		}
		if !strings.Contains(comp.Basis, "scope changed") {
			t.Fatalf("freshness basis = %q, want it to name the scope change", comp.Basis)
		}
		// The basis must disclose a range, not a single fabricated instant.
		if !strings.Contains(comp.Basis, "within the last") {
			t.Fatalf("freshness basis = %q, want a bounded range", comp.Basis)
		}
	}
	if !found {
		t.Fatal("alpha was not evaluated")
	}
}

// A cheap listing sweep advances LastSeenAt without reading scope. It must not
// therefore move the scope interval: using LastSeenAt as the lower bound would
// claim the scope was observed minutes ago when it was last observed hours ago.
func TestListingSweepDoesNotAdvanceTheScopeInterval(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	changed := base.Add(9 * time.Minute)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, changed)

	atChange := loadProgram(t, dir, "alpha")
	if !atChange.ScopeChanged.Known() {
		t.Fatal("the scan that detected the change must record an interval")
	}
	originalNotBefore := atChange.ScopeChanged.NotBefore

	// Five sweeps that never read the detail page. LastSeenAt advances on each.
	for i := 1; i <= 5; i++ {
		scanListingOnly(t, src, dir, changed.Add(time.Duration(i)*time.Hour))

		p := loadProgram(t, dir, "alpha")
		if !p.ScopeChanged.Known() {
			t.Fatalf("sweep %d discarded the scope interval", i)
		}
		if !p.ScopeChanged.NotBefore.Equal(originalNotBefore) {
			t.Fatalf("sweep %d moved the lower bound to %s, want %s",
				i, p.ScopeChanged.NotBefore, originalNotBefore)
		}
		if !p.ScopeChanged.NotAfter.Equal(changed) {
			t.Fatalf("sweep %d moved the upper bound to %s, want %s",
				i, p.ScopeChanged.NotAfter, changed)
		}
	}
}

// A first observation is not a change. Nothing was observed before, so nothing
// can be said about when the fingerprints moved, and a record must not claim
// otherwise.
func TestFirstObservationRecordsNoChangeInterval(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	scanAt(t, src, dir, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))

	p := loadProgram(t, dir, "alpha")
	if p.ScopeChanged.Known() {
		t.Fatalf("a first observation must not record a scope interval, got %s", p.ScopeChanged)
	}
	if p.RequirementsChanged.Known() {
		t.Fatal("a first observation must not record a requirement interval")
	}
	if p.MetadataChanged.Known() {
		t.Fatal("a first observation must not record a metadata interval")
	}
}

// Requirement intervals behave exactly as scope intervals do.
func TestRequirementIntervalSurvivesSubsequentScans(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	src.mu.Lock()
	rec := src.records["alpha"]
	rec.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 40}
	src.records["alpha"] = rec
	src.mu.Unlock()

	changed := base.Add(11 * time.Minute)
	scanAt(t, src, dir, changed)

	atChange := loadProgram(t, dir, "alpha")
	if !atChange.RequirementsChanged.Known() {
		t.Fatal("a reputation change must record a requirement interval")
	}

	later := changed.Add(9 * time.Hour)
	scanAt(t, src, dir, later)

	final := loadProgram(t, dir, "alpha")
	if !final.RequirementsChanged.Known() {
		t.Fatal("the requirement interval must survive later scans")
	}
	if !final.RequirementsChanged.NotAfter.Equal(atChange.RequirementsChanged.NotAfter) {
		t.Fatalf("requirement interval upper bound drifted to %s, want %s",
			final.RequirementsChanged.NotAfter, atChange.RequirementsChanged.NotAfter)
	}
}

// A second, distinct change replaces the interval with one describing the new
// transition. The prior transition's evidence lives in history, not in the
// program record, which tracks only the most recent move.
func TestASecondChangeReplacesTheInterval(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	first := base.Add(9 * time.Minute)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, first)

	second := first.Add(3 * time.Hour)
	addAPIScope(src, "alpha", "https://api-v3.alpha.example.com")
	scanAt(t, src, dir, second)

	final := loadProgram(t, dir, "alpha")
	if !final.ScopeChanged.Known() {
		t.Fatal("the interval must be known after a second change")
	}
	if !final.ScopeChanged.NotAfter.Equal(second) {
		t.Fatalf("upper bound = %s, want the second transition at %s",
			final.ScopeChanged.NotAfter, second)
	}
	if final.ScopeChanged.NotBefore.Equal(base) {
		t.Fatal("the lower bound must advance to the observation preceding the second change")
	}
}

// Two scans that see the same upstream bytes must produce the same interval. A
// clock that advances without any observation happening must not manufacture
// evidence.
func TestIntervalIsStableAcrossIdenticalObservations(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	changed := base.Add(9 * time.Minute)
	scanAt(t, src, dir, changed)

	first := loadProgram(t, dir, "alpha").ScopeChanged
	for i := 1; i <= 3; i++ {
		scanAt(t, src, dir, changed.Add(time.Duration(i)*7*24*time.Hour))
		again := loadProgram(t, dir, "alpha").ScopeChanged
		if again != first {
			t.Fatalf("scan %d changed the interval: got %s, want %s", i, again, first)
		}
	}
}

// removeAPIScope drops a previously added API asset.
func removeAPIScope(src *fakeSource, id string, target string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	kept := rec.Scopes[:0]
	for _, sc := range rec.Scopes {
		if sc.Target == target {
			continue
		}
		kept = append(kept, sc)
	}
	rec.Scopes = append([]domain.RawScope(nil), kept...)
	src.records[id] = rec
}

// discardLogger returns a logger that drops everything, for tests that assert on
// results rather than on output.
func discardLogger() *obs.Logger { return obs.Discard() }
