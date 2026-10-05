package pipeline_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
)

// The scenarios named in the directive, exercised end to end through the real
// pipeline against a real state store.
//
// The harness forces a detail read on every scan. That is deliberate: the
// two-tier read means a change is detected at the first detail read AFTER it
// happened, so without forcing it these tests would measure the refresh interval
// rather than the trigger behaviour they are pinning.
//
// The one exception is TestAcceptanceUnknownChangeIntervalSilencesEverything,
// which is specifically about the cheap path.

var accBase = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// aged turns a program into one that launched years ago.
func aged(src *fakeSource, id string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	rec.RawDates.Start = "01 Jan 2021"
	src.records[id] = rec
}

func setReputation(src *fakeSource, id string, points int) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	rec.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: points}
	src.records[id] = rec
}

func setKYC(src *fakeSource, id string, v domain.Tri) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	rec.KYC = v
	src.records[id] = rec
}

func setFee(src *fakeSource, id string, usd float64) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	if usd == 0 {
		rec.Fee = domain.FeeGate{Present: domain.TriNo}
	} else {
		rec.Fee = domain.FeeGate{Present: domain.TriYes, USD: usd}
	}
	src.records[id] = rec
}

func setSubmissions(src *fakeSource, id string, n int) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	v := n
	rec.SubmittedReports = &v
	rec.SubmittedReportsKnown = true
	src.records[id] = rec
	for i := range src.refs {
		if src.refs[i].ID != id {
			continue
		}
		src.refs[i].Listing.SubmittedReports = &v
		src.refs[i].Listing.SubmittedReportsKnown = true
		src.refs[i].SubmittedReports = &v
		src.refs[i].SubmittedReportsKnown = true
	}
}

// setStatus changes both the record and the listing, so the cheap tier agrees
// with the detail page and the two-tier read stays consistent.
func setStatus(src *fakeSource, id string, status string) {
	src.mu.Lock()
	defer src.mu.Unlock()
	rec := src.records[id]
	rec.Status = status
	src.records[id] = rec
	for i := range src.refs {
		if src.refs[i].ID == id {
			src.refs[i].Listing.Status = status
		}
	}
}

// settle brings a program into a known stored state: one baseline scan plus one
// confirmation scan, so that the next scan's comparison is against a settled
// record rather than against first observation.
func settle(t *testing.T, src domain.ProgramSource, dir string, at time.Time) {
	t.Helper()
	scanAt(t, src, dir, at)
	scanAt(t, src, dir, at.Add(time.Minute))
}

func alertsFor(t *testing.T, res pipeline.Result, id string) []domain.Alert {
	t.Helper()
	out := make([]domain.Alert, 0, 4)
	for _, a := range res.Alerts {
		if a.ProgramID == id {
			out = append(out, a)
		}
	}
	return out
}

func mustAlert(t *testing.T, res pipeline.Result, id, why string) domain.Alert {
	t.Helper()
	got := alertsFor(t, res, id)
	if len(got) == 0 {
		t.Fatalf("%s: expected an alert", why)
	}
	return got[0]
}

func mustNotAlert(t *testing.T, res pipeline.Result, id, why string) {
	t.Helper()
	if got := alertsFor(t, res, id); len(got) > 0 {
		t.Fatalf("%s: expected silence, got %q", why, got[0].Subject)
	}
}

// 1. A five-year-old program that gains an API alerts, despite its age.
func TestAcceptanceOldProgramNewAPIAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	aged(src, "alpha")
	settle(t, src, dir, accBase.Add(2*time.Minute))

	p := loadProgram(t, dir, "alpha")
	if age, _ := p.Age(accBase); age < 5*365*24*time.Hour {
		t.Fatalf("test setup: program age = %s, want over five years", age)
	}

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))

	a := mustAlert(t, res, "fake:alpha", "a five-year-old program gained an API")
	if !strings.Contains(strings.ToLower(a.Subject+a.Body), "api") {
		t.Errorf("the alert does not mention the API: %q", a.Subject)
	}
	// The alert must disclose that the program is old, so the reader is not misled.
	if !strings.Contains(a.Body, "Timing") {
		t.Error("the alert carries no timing section")
	}
}

// 2. The same change with an unbounded interval is silent.
func TestAcceptanceUnknownChangeIntervalSilencesEverything(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	// Never read a detail page, so nothing ever establishes the transition.
	res := scanListingOnly(t, src, dir, accBase.Add(4*time.Minute))
	mustNotAlert(t, res, "fake:alpha", "the change interval is unknown")

	// And the stored record must not have invented one.
	if loadProgram(t, dir, "alpha").ScopeChanged.Known() {
		t.Fatal("a cheap sweep must not manufacture a change interval")
	}
}

// 3. A lowered reputation requirement alerts.
func TestAcceptanceLoweredReputationAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	aged(src, "alpha")
	setReputation(src, "alpha", 70)
	scanAt(t, src, dir, accBase.Add(2*time.Minute))
	scanAt(t, src, dir, accBase.Add(3*time.Minute))

	setReputation(src, "alpha", 20)
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustAlert(t, res, "fake:alpha", "the reputation requirement was lowered")
}

// 4. A removed KYC requirement alerts.
func TestAcceptanceKYCRemovedAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	// Settle with KYC required, then remove it. The program is aged first so the
	// alert cannot be attributed to its launch date.
	setKYC(src, "alpha", domain.TriYes)
	settle(t, src, dir, accBase)
	aged(src, "alpha")
	scanAt(t, src, dir, accBase.Add(2*time.Minute))

	setKYC(src, "alpha", domain.TriNo)
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustAlert(t, res, "fake:alpha", "the KYC requirement was removed")
}

// 5. A scope change on an old program alerts.
func TestAcceptanceOldProgramScopeChangeAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	aged(src, "alpha")
	scanAt(t, src, dir, accBase.Add(2*time.Minute))

	addAPIScope(src, "alpha", "https://api-v3.alpha.example.com")
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustAlert(t, res, "fake:alpha", "an old program's scope changed")
}

// 6. New-program alerting still works, unchanged.
func TestAcceptanceNewProgramStillAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	res := scanAt(t, src, dir, accBase)
	a := mustAlert(t, res, "fake:alpha", "a newly launched program")
	if a.Kind != domain.AlertNewQualifying {
		t.Errorf("kind = %s, want NEW_QUALIFYING", a.Kind)
	}
	if !strings.Contains(a.Subject, "NEW MATCH") {
		t.Errorf("subject = %q, want the new-program headline", a.Subject)
	}
}

// 7. A reactivation alerts independently of the program's age.
func TestAcceptanceReactivationAlertsRegardlessOfAge(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	aged(src, "alpha")

	setStatus(src, "alpha", "PAUSED")
	settle(t, src, dir, accBase.Add(2*time.Minute))

	setStatus(src, "alpha", "LIVE")
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))

	a := mustAlert(t, res, "fake:alpha", "a five-year-old program was reactivated")
	if !a.Changes.Contains(domain.ChangeProgramReactivated) {
		t.Errorf("changes = %v, want a reactivation", a.Changes.Kinds())
	}
}

// 8. The same change seen again produces no second alert.
func TestAcceptanceRepeatedObservationDoesNotRealert(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	first := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	fp := mustAlert(t, first, "fake:alpha", "the scope change").Fingerprint

	for i := 2; i <= 5; i++ {
		res := scanAt(t, src, dir, accBase.Add(time.Duration(i)*time.Minute))
		mustNotAlert(t, res, "fake:alpha", "the same change must not alert twice")
	}

	// The alert record survives, so the condition is still known to have fired.
	rec, err := state.NewFileStore(dir).AlertRecordFor(context.Background(), fp)
	if err != nil {
		t.Fatalf("the original alert record is gone: %v", err)
	}
	if rec.Fingerprint != fp {
		t.Error("the alert record no longer matches the alert that was sent")
	}
}

// 9. Losing an API is recorded but raises nothing on its own.
func TestAcceptanceLostAPIIsSilent(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	removeAPIScope(src, "alpha", "https://api.alpha.example.com")
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustNotAlert(t, res, "fake:alpha", "losing an API is not an opening")

	// It must still be recorded, because the next comparison depends on it.
	entries, err := state.NewFileStore(dir).HistoryFor(context.Background(), "fake:alpha")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Changes.Contains(domain.ChangeAPIRemoved) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the removal was not recorded in history: %v", entries)
	}
}

// 10. Removing an API and adding it back produces a second opportunity.
func TestAcceptanceReAddedAPIProducesASecondOpportunity(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	firstAlert := mustAlert(t, scanAt(t, src, dir, accBase.Add(4*time.Minute)),
		"fake:alpha", "the first API addition")
	scanAt(t, src, dir, accBase.Add(5*time.Minute))
	scanAt(t, src, dir, accBase.Add(6*time.Minute))

	removeAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, accBase.Add(7*time.Minute))
	scanAt(t, src, dir, accBase.Add(8*time.Minute))

	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	second := scanAt(t, src, dir, accBase.Add(10*time.Minute))
	secondAlert := mustAlert(t, second, "fake:alpha", "the API was re-added")

	if secondAlert.Fingerprint == firstAlert.Fingerprint {
		t.Error("re-adding the same API produced an identical fingerprint; " +
			"two distinct opportunities must be distinguishable")
	}
}

// 11. A rising submission count is recorded and creates nothing.
func TestAcceptanceSubmissionRiseIsSilent(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	setSubmissions(src, "alpha", 180)
	settle(t, src, dir, accBase)

	setSubmissions(src, "alpha", 184)
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustNotAlert(t, res, "fake:alpha", "a moving submission count must never alert")
}

// 12. A falling submission count is handled without a negative-age artefact.
func TestAcceptanceSubmissionFallKeepsTheCountSane(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	setSubmissions(src, "alpha", 184)
	settle(t, src, dir, accBase)

	setSubmissions(src, "alpha", 179)
	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	mustNotAlert(t, res, "fake:alpha", "a falling submission count must never alert")

	p := loadProgram(t, dir, "alpha")
	if !p.SubmittedReportsKnown || p.SubmittedReports == nil {
		t.Fatal("the submission count became unknown; a decrease must not erase it")
	}
	if *p.SubmittedReports != 179 {
		t.Fatalf("submission count = %d, want the observed 179", *p.SubmittedReports)
	}
}

// 13. Windows survive a restart, and 14. corruption fails loudly.
func TestAcceptanceWindowsSurviveAndCorruptionFailsLoudly(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
	scanAt(t, src, dir, accBase.Add(4*time.Minute))

	store := state.NewFileStore(dir)
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeProg, ok := before.Program("fake:alpha")
	if !ok {
		t.Fatal("alpha is missing from state")
	}
	if !beforeProg.ScopeChanged.Known() {
		t.Fatal("the change interval was not persisted")
	}

	// A fresh store over the same directory reads the same evidence back.
	after, err := state.NewFileStore(dir).Load(context.Background())
	if err != nil {
		t.Fatalf("a fresh store could not read the state back: %v", err)
	}
	afterProg, ok := after.Program("fake:alpha")
	if !ok {
		t.Fatal("alpha is missing after reload")
	}
	if afterProg.ScopeChanged != beforeProg.ScopeChanged {
		t.Error("the change interval did not survive a reload")
	}

	// Corruption must be reported, never silently discarded. Discarding would
	// make every program look new and fire an alert for all of them.
	corrupt := t.TempDir()
	if err := os.WriteFile(corrupt+"/programs.json", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := state.NewFileStore(corrupt).Load(context.Background()); err == nil {
		t.Fatal("corrupt state loaded silently; that would reset every opportunity")
	}
}

// 15. A dry run records exactly the alert a live run would deliver.
func TestAcceptanceDryRunAndLiveProduceIdenticalContent(t *testing.T) {
	profile := testProfile(t)

	_ = profile
	build := func(dir string, dry bool) domain.Alert {
		src := newFakeSource("alpha")
		settle(t, src, dir, accBase)
		addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")

		clock := accBase.Add(4 * time.Minute)
		res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
			c.Now = func() time.Time { return clock }
			c.Profile.Scan.DetailsRefreshInterval = 1
			c.DryRun = dry
		})
		if err != nil {
			t.Fatal(err)
		}
		got := alertsFor(t, res, "fake:alpha")
		if len(got) != 1 {
			t.Fatalf("expected exactly one alert, got %d", len(got))
		}
		return got[0]
	}

	dry := build(t.TempDir(), true)
	live := build(t.TempDir(), false)

	if dry.Fingerprint != live.Fingerprint {
		t.Error("a dry run and a live run produced different fingerprints")
	}
	if dry.Subject != live.Subject {
		t.Errorf("subject differs:\n dry: %q\nlive: %q", dry.Subject, live.Subject)
	}
	if dry.Body != live.Body {
		t.Error("body differs between a dry run and a live run")
	}
	if dry.HTMLBody != live.HTMLBody {
		t.Error("HTML body differs between a dry run and a live run")
	}
}

// 17 and 18. The stored evidence can reconstruct why an alert fired.
func TestAcceptanceHistoryAndExplainReconstructTheReason(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	settle(t, src, dir, accBase)
	aged(src, "alpha")
	scanAt(t, src, dir, accBase.Add(2*time.Minute))

	setReputation(src, "alpha", 70)
	scanAt(t, src, dir, accBase.Add(3*time.Minute))
	setReputation(src, "alpha", 20)
	addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")

	res := scanAt(t, src, dir, accBase.Add(4*time.Minute))
	a := mustAlert(t, res, "fake:alpha", "a compound change alerted")

	store := state.NewFileStore(dir)

	// explain: the stored record must still carry the bounded evidence.
	p := loadProgram(t, dir, "alpha")
	if !p.ScopeChanged.Known() || !p.RequirementsChanged.Known() {
		t.Fatal("explain cannot reconstruct the alert: a change interval is missing")
	}

	// history: the atomic deltas must be individually visible.
	entries, err := store.HistoryFor(context.Background(), "fake:alpha")
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if !last.Changes.Contains(domain.ChangeAPIAdded) {
		t.Errorf("history is missing the API addition: %v", last.Kinds)
	}
	if !last.Changes.Contains(domain.ChangeReputationLowered) {
		t.Errorf("history is missing the directional reputation delta: %v", last.Kinds)
	}
	// Both must be present as separate facts, not fused into one claim.
	if last.Changes.Contains(domain.ChangeReputationChanged) &&
		!last.Changes.Contains(domain.ChangeReputationLowered) {
		t.Error("history recorded the undirected change but lost the direction")
	}
	if !a.Changes.Contains(domain.ChangeAPIAdded) || !a.Changes.Contains(domain.ChangeReputationLowered) {
		t.Errorf("the alert fused or dropped deltas: %v", a.Changes.Kinds())
	}
}

// 19. Upgrading must not manufacture historical opportunities.
func TestAcceptanceFirstRunAfterUpgradeManufacturesNothing(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()

	// Every program is old and every program is new to this build.
	aged(src, "alpha")
	aged(src, "beta")

	res := scanAt(t, src, dir, accBase)
	for _, e := range res.Programs {
		p := e.Program
		if p.ScopeChanged.Known() || p.RequirementsChanged.Known() ||
			p.MetadataChanged.Known() || p.LifecycleChanged.Known() {
			t.Fatalf("%s: a first observation recorded a change interval: %s",
				p.ID, p.ScopeChanged)
		}
	}

	// A second scan with identical upstream bytes must produce nothing at all.
	quiet := scanAt(t, src, dir, accBase.Add(time.Minute))
	for _, e := range quiet.Programs {
		if e.Diff.IsNew || !e.Diff.Changes.Empty() {
			t.Errorf("%s: an identical observation produced changes: %v",
				e.Program.ID, e.Diff.Changes.Kinds())
		}
		if e.Program.ScopeChanged.Known() {
			t.Errorf("%s: an identical observation moved a change interval", e.Program.ID)
		}
	}
}

// 20. Identical upstream observations produce byte-identical state.
func TestAcceptanceIdenticalObservationsProduceIdenticalBytes(t *testing.T) {
	run := func(dir string) []byte {
		src := newFakeSource("alpha", "beta", "gamma")
		settle(t, src, dir, accBase)
		addAPIScope(src, "alpha", "https://api-v2.alpha.example.com")
		setReputation(src, "beta", 30)
		scanAt(t, src, dir, accBase.Add(4*time.Minute))
		scanAt(t, src, dir, accBase.Add(9*time.Minute))

		raw, err := os.ReadFile(dir + "/programs.json")
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	first := run(t.TempDir())
	second := run(t.TempDir())
	if string(first) != string(second) {
		t.Error("two runs over identical upstream bytes produced different state")
	}
}
