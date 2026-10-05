package pipeline_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
)

func storedWindows(t *testing.T, dir string) []domain.OpportunityWindow {
	t.Helper()
	snap, err := state.NewFileStore(dir).Load(context.Background())
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	out := make([]domain.OpportunityWindow, 0, len(snap.Windows))
	for _, window := range snap.Windows {
		out = append(out, window)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func removeAPIScope(src *fakeSource, id, target string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	filtered := make([]domain.RawScope, 0, len(rec.Scopes))
	for _, scope := range rec.Scopes {
		if scope.Target != target {
			filtered = append(filtered, scope)
		}
	}
	rec.Scopes = filtered
	src.records[id] = rec
}

func TestWindowLifecycleUsesOneIdentityPerOpeningTransition(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	target := "https://api-v2.alpha.example.com"

	scanAt(t, src, dir, base)
	addAPIScope(src, "alpha", target)
	scanAt(t, src, dir, base.Add(2*time.Minute))
	first := storedWindows(t, dir)
	if len(first) != 1 {
		t.Fatalf("windows after the first opening = %d, want 1", len(first))
	}
	firstID := first[0].ID
	firstObserved := first[0].Observed

	// Seeing the same transition again cannot create a second event. Its
	// identity and temporal evidence remain unchanged across the scan.
	scanAt(t, src, dir, base.Add(3*time.Minute))
	repeated := storedWindows(t, dir)
	if len(repeated) != 1 || repeated[0].ID != firstID {
		t.Fatalf("repeated observation changed the window set: %+v", repeated)
	}
	if repeated[0].Observed != firstObserved {
		t.Errorf("repeated observation rewrote the interval: got %s, want %s",
			repeated[0].Observed, firstObserved)
	}

	// A removal is recorded in history but is not an opening.
	removeAPIScope(src, "alpha", target)
	scanAt(t, src, dir, base.Add(4*time.Minute))
	if got := storedWindows(t, dir); len(got) != 1 {
		t.Fatalf("scope removal opened a window; got %d", len(got))
	}

	// Re-adding the same asset is a new transition with a distinct identity.
	addAPIScope(src, "alpha", target)
	scanAt(t, src, dir, base.Add(5*time.Minute))
	final := storedWindows(t, dir)
	if len(final) != 2 {
		t.Fatalf("windows after add/remove/add = %d, want 2", len(final))
	}
	if final[0].ID == final[1].ID {
		t.Fatal("the two additions share an identity")
	}
	if final[0].ID != firstID && final[1].ID != firstID {
		t.Fatal("the original transition's identity was not retained")
	}
}

func TestUnknownOpeningCountIsNotRebasedOnALaterListing(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, base.Add(time.Minute))
	opened := storedWindows(t, dir)
	if len(opened) != 1 || opened[0].BaselineSubmissions != nil {
		t.Fatalf("opening count should be unknown, got %+v", opened)
	}

	// Later listing observations are useful current counts, but they are not the
	// count that was visible when the opportunity opened.
	setSubmissions(src, "alpha", 8)
	scanListingOnly(t, src, dir, base.Add(2*time.Minute))
	updated := storedWindows(t, dir)[0]
	if updated.BaselineSubmissions != nil || updated.SubmissionsSinceOpen != nil {
		t.Fatalf("later count was incorrectly relabelled as the opening baseline: %+v", updated)
	}
	if updated.CurrentSubmissions == nil || *updated.CurrentSubmissions != 8 {
		t.Fatalf("latest listing count was not recorded: %+v", updated)
	}
}

func TestWindowSubmissionBaselineIsCapturedOnceAndSigned(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	setSubmissions(src, "alpha", 12)
	scanAt(t, src, dir, base)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, base.Add(time.Minute))
	opened := storedWindows(t, dir)
	if len(opened) != 1 {
		t.Fatalf("windows = %d, want 1", len(opened))
	}
	id := opened[0].ID
	if opened[0].BaselineSubmissions == nil || *opened[0].BaselineSubmissions != 12 {
		t.Fatalf("baseline = %v, want 12", opened[0].BaselineSubmissions)
	}

	setSubmissions(src, "alpha", 15)
	scanAt(t, src, dir, base.Add(2*time.Minute))
	increased := storedWindows(t, dir)[0]
	if *increased.BaselineSubmissions != 12 || *increased.CurrentSubmissions != 15 ||
		*increased.SubmissionsSinceOpen != 3 {
		t.Fatalf("increase rewrote or miscomputed the measurement: %+v", increased)
	}

	setSubmissions(src, "alpha", 8)
	scanAt(t, src, dir, base.Add(3*time.Minute))
	decreased := storedWindows(t, dir)[0]
	if decreased.ID != id {
		t.Fatal("a count movement changed the transition identity")
	}
	if *decreased.BaselineSubmissions != 12 || *decreased.CurrentSubmissions != 8 ||
		*decreased.SubmissionsSinceOpen != -4 {
		t.Fatalf("decrease was not measured from the original baseline: %+v", decreased)
	}
}

func TestWindowExpiryByAgeCrowdingAndUnknownEvidence(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	observed := domain.NewObservationInterval(base, base.Add(time.Minute))
	w := domain.OpportunityWindow{Observed: observed}

	if got := w.Status(base.Add(2*time.Hour), domain.OpportunityWindowOptions{MaxAge: time.Hour}); got != domain.WindowExpired {
		t.Errorf("age expiry status = %s, want expired", got)
	}

	movement := 5
	w.SubmissionsSinceOpen = &movement
	if got := w.Status(base.Add(2*time.Minute), domain.OpportunityWindowOptions{MaxAge: 24 * time.Hour, MaxPostChangeSubmissions: 5}); got != domain.WindowExpired {
		t.Errorf("crowding expiry status = %s, want expired", got)
	}
	movement = -4
	if got := w.Status(base.Add(2*time.Minute), domain.OpportunityWindowOptions{MaxPostChangeSubmissions: 5}); got != domain.WindowOpen {
		t.Errorf("a negative submission movement expired the window: %s", got)
	}

	unknown := domain.OpportunityWindow{}
	if got := unknown.Status(base, domain.OpportunityWindowOptions{MaxAge: 24 * time.Hour}); got != domain.WindowExpired {
		t.Errorf("unbounded window status = %s, want expired", got)
	}
}

func TestWindowIdentityIsStableAcrossScansAndDistinctAcrossTransitions(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	observed := domain.NewObservationInterval(now.Add(-2*time.Minute), now)
	deltas := domain.Deltas{{
		Field: "scope", Kind: domain.ChangeAPIAdded,
		Direction: domain.DirectionImproved, Assets: []string{"https://api.example.test"},
	}}
	first := domain.NewOpportunityWindow("fake:alpha", "Alpha", observed, deltas,
		domain.OpportunityWindowOptions{ScanID: "scan-one"})
	repeated := domain.NewOpportunityWindow("fake:alpha", "Alpha", observed, deltas,
		domain.OpportunityWindowOptions{ScanID: "scan-two"})
	if first.ID != repeated.ID {
		t.Fatalf("same transition changed identity across scans: %s != %s", first.ID, repeated.ID)
	}

	secondObservation := domain.NewObservationInterval(now.Add(time.Minute), now.Add(2*time.Minute))
	second := domain.NewOpportunityWindow("fake:alpha", "Alpha", secondObservation, deltas,
		domain.OpportunityWindowOptions{ScanID: "scan-three"})
	if first.ID == second.ID {
		t.Fatal("distinct transitions with identical deltas share an identity")
	}
}

func TestCompoundWindowKeepsAtomicDirectionalDeltas(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	setKYC(src, "alpha", domain.TriYes)
	setReputation(src, "alpha", 70)
	scanAt(t, src, dir, base)
	scanAt(t, src, dir, base.Add(time.Minute))

	setKYC(src, "alpha", domain.TriNo)
	setReputation(src, "alpha", 20)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, base.Add(2*time.Minute))

	windows := storedWindows(t, dir)
	if len(windows) != 1 {
		t.Fatalf("compound transition opened %d windows, want 1", len(windows))
	}
	kinds := windows[0].Deltas.Kinds()
	for _, want := range []string{
		string(domain.ChangeAPIAdded),
		string(domain.ChangeReputationLowered),
		string(domain.ChangeKYCRemoved),
	} {
		if !containsString(kinds, want) {
			t.Errorf("compound window is missing atomic delta %s: %v", want, kinds)
		}
	}
	if containsString(kinds, "ACCESS_OPENED") {
		t.Errorf("window fused its atomic evidence into an editorial claim: %v", kinds)
	}
}

func TestWindowQueryDerivesOpenStatusAndFilters(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scanAt(t, src, dir, base)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, base.Add(time.Minute))

	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time {
		return base.Add(2 * time.Minute)
	})
	all, err := q.Windows(context.Background(), pipeline.WindowsRequest{})
	if err != nil {
		t.Fatalf("query windows: %v", err)
	}
	if len(all) != 1 || all[0].Status != domain.WindowOpen {
		t.Fatalf("all windows = %+v, want one open window", all)
	}
	open, err := q.Windows(context.Background(), pipeline.WindowsRequest{OpenOnly: true, Program: "alpha"})
	if err != nil {
		t.Fatalf("query open windows: %v", err)
	}
	if len(open) != 1 || open[0].Window.ProgramID != "fake:alpha" {
		t.Fatalf("filtered windows = %+v, want alpha's open window", open)
	}

	q = pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time {
		return base.Add(73 * time.Hour)
	})
	expired, err := q.Windows(context.Background(), pipeline.WindowsRequest{})
	if err != nil {
		t.Fatalf("query expired windows: %v", err)
	}
	if len(expired) != 1 || expired[0].Status != domain.WindowExpired {
		t.Fatalf("derived status = %+v, want one expired window", expired)
	}
	open, err = q.Windows(context.Background(), pipeline.WindowsRequest{OpenOnly: true})
	if err != nil {
		t.Fatalf("query open-only windows: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("open-only query returned %d expired window(s)", len(open))
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
