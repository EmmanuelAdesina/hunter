package pipeline_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/notify"
	"github.com/eadeshina/hunter/internal/obs"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/source"
	"github.com/eadeshina/hunter/internal/state"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const profileYAML = `
profile:
  name: test
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
    accept_unknown_access_gates: false
    accept_unknown_parse_state: false
  target_domains:
    included: [web_application, api, codebase]
  crypto:
    enabled: true
    mode: auto
    require_allowed_trait: true
    allowed: [crypto_platform, exchange, crypto_api]
    excluded: [smart_contract_only, protocol_consensus]
    dominance_ratio: 0.6
  program_states:
    allowed: [live, new]
  notifications:
    enabled: true
    min_severity: medium
    require_eligible: true
    alert_on_new_programs: true
    new_program_window: 24h
    change_windows:
      default: 72h
    alert_on_material_change: true
    alert_on_newly_eligible: true
    alert_on_scope_expansion: true
    max_per_scan: 0
  scan:
    fetch_details: true
    fetch_details_on_listing_change: true
    details_refresh_interval: 24h
`

func testProfile(t *testing.T) *config.Profile {
	t.Helper()
	p, err := config.Parse([]byte(profileYAML))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	return p
}

// fakeSource is a programmable source adapter.
// fakeSource is a programmable source adapter.
//
// It guards its own state because the pipeline fetches concurrently, which is
// exactly how a real adapter behaves.
type fakeSource struct {
	mu          sync.Mutex
	refs        []domain.ProgramRef
	records     map[string]domain.RawProgram
	failOn      map[string]error
	fetches     map[string]int
	discoverErr error
	now         time.Time
}

func newFakeSource(ids ...string) *fakeSource {
	s := &fakeSource{
		records: map[string]domain.RawProgram{},
		failOn:  map[string]error{},
		fetches: map[string]int{},
		now:     fixedNow,
	}
	for _, id := range ids {
		s.refs = append(s.refs, domain.ProgramRef{
			Source: "fake", ID: id, Slug: id, Name: "Program " + id,
			URL:     "https://fake.test/programs/" + id,
			Listing: domain.Listing{Status: "LIVE", State: "published", RewardRaw: "$5,000"},
		})
		s.records[id] = defaultRecord(id)
	}
	return s
}

func defaultRecord(id string) domain.RawProgram {
	return domain.RawProgram{
		Parsed:          true,
		Name:            "Program " + id,
		Status:          "LIVE",
		State:           "published",
		Reputation:      domain.ReputationGate{Present: domain.TriNo},
		Fee:             domain.FeeGate{Present: domain.TriNo},
		KYC:             domain.TriNo,
		POC:             domain.TriYes,
		MaxBountyRaw:    "5000.0",
		CategoriesRaw:   []string{"Web", "API"},
		ProjectTypesRaw: []string{"CEX"},
		Description:     "A cryptocurrency exchange with a web application and REST API.",
		RawDates:        domain.RawDates{Start: "01 Oct 2026"},
		Scopes: []domain.RawScope{
			{Title: "Web", Target: "*." + id + ".example.com"},
			{Title: "API", Target: "https://api." + id + ".example.com"},
		},
	}
}

func (s *fakeSource) Name() string { return "fake" }

func (s *fakeSource) Capabilities() domain.SourceCapabilities {
	return domain.SourceCapabilities{MaxConcurrent: 2, HasStableIDs: true}
}

func (s *fakeSource) Discover(ctx context.Context) ([]domain.ProgramRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refs, s.discoverErr
}

func (s *fakeSource) Fetch(ctx context.Context, ref domain.ProgramRef) (domain.RawProgram, error) {
	if err := ctx.Err(); err != nil {
		return domain.RawProgram{Ref: ref}, err
	}
	// The pipeline fetches concurrently, so the double must guard its own state.
	s.mu.Lock()
	s.fetches[ref.ID]++
	fail, hasFail := s.failOn[ref.ID]
	rec, hasRec := s.records[ref.ID]
	s.mu.Unlock()

	if hasFail {
		return domain.RawProgram{Ref: ref}, fail
	}
	if !hasRec {
		return domain.RawProgram{Ref: ref}, source.ErrParse
	}
	rec.Ref = ref
	return rec, nil
}

// fetchCount reports how many detail reads a program received.
func (s *fakeSource) fetchCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches[id]
}

// recordingNotifier captures delivered alerts.
type recordingNotifier struct {
	delivered []domain.Alert
	err       error
}

func (n *recordingNotifier) Send(_ context.Context, a domain.Alert) error {
	if n.err != nil {
		return n.err
	}
	n.delivered = append(n.delivered, a)
	return nil
}
func (n *recordingNotifier) Name() string     { return "recording" }
func (n *recordingNotifier) Configured() bool { return true }

type failingDeliveryStore struct {
	state.StateStore
	err error
}

func (s failingDeliveryStore) MarkAlertDelivered(context.Context, string, time.Time) error {
	return s.err
}

// runScanner wires a scanner over a source and state directory.
func runScanner(t *testing.T, src domain.ProgramSource, dir string, mutators ...func(*pipeline.Config)) (pipeline.Result, error) {
	t.Helper()
	cfg := pipeline.Config{
		Profile:      testProfile(t),
		Sources:      []domain.ProgramSource{src},
		Store:        state.NewFileStore(dir),
		Logger:       obs.Discard(),
		Now:          func() time.Time { return fixedNow },
		FetchDetails: true,
		Concurrency:  2,
	}
	for _, m := range mutators {
		m(&cfg)
	}
	s, err := pipeline.New(cfg)
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	return s.Scan(context.Background())
}

// TestFirstScanFindsEverything verifies a cold scan discovers, evaluates, and
// alerts on qualifying programs.
func TestFirstScanFindsEverything(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Metrics.Discovered != 2 {
		t.Errorf("discovered = %d, want 2", res.Metrics.Discovered)
	}
	if res.Metrics.New != 2 {
		t.Errorf("new = %d, want 2", res.Metrics.New)
	}
	if res.Metrics.Eligible != 2 {
		t.Errorf("eligible = %d, want 2 (%v)", res.Metrics.Eligible, res.Errors)
	}
	if len(res.Alerts) != 2 {
		t.Errorf("alerts = %d, want 2", len(res.Alerts))
	}
}

// TestCatchUpDetailBudgetIsSharedAcrossConcurrentEvaluations verifies the
// configured per-scan cap is consumed exactly once per detail request despite
// concurrent program evaluation.
func TestCatchUpDetailBudgetIsSharedAcrossConcurrentEvaluations(t *testing.T) {
	ids := make([]string, 24)
	for i := range ids {
		ids[i] = fmt.Sprintf("program-%02d", i)
	}
	src := newFakeSource(ids...)

	_, _ = runScanner(t, src, t.TempDir(), func(c *pipeline.Config) {
		c.Profile.Scan.MaxCatchUpDetailFetchesPerScan = 3
		c.Concurrency = 16
	})

	fetched := 0
	for _, id := range ids {
		fetched += src.fetchCount(id)
	}
	if fetched != 3 {
		t.Errorf("detail fetches = %d, want the shared catch-up cap of 3", fetched)
	}
}

// TestSecondScanIsIdempotent verifies a repeat scan of unchanged data produces
// no alerts and no new programs. This is the property that prevents the channel
// from filling with the same opportunity every five minutes.
func TestSecondScanIsIdempotent(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()

	first, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Alerts) != 2 {
		t.Fatalf("first scan alerts = %d, want 2", len(first.Alerts))
	}

	second, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Alerts) != 0 {
		t.Errorf("second scan produced %d alerts for unchanged data: %+v", len(second.Alerts), second.Alerts)
	}
	if second.Metrics.New != 0 {
		t.Errorf("second scan reported %d new programs", second.Metrics.New)
	}
	if second.Metrics.Changed != 0 {
		t.Errorf("second scan reported %d changed programs", second.Metrics.Changed)
	}
}

// TestDetailFetchIsSkippedWhenListingIsUnchanged verifies the two-tier read
// actually short-circuits, since this is what keeps a five-minute cadence
// affordable.
func TestDetailFetchIsSkippedWhenListingIsUnchanged(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()

	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}
	if src.fetchCount("alpha") != 1 {
		t.Fatalf("first scan fetched alpha %d times, want 1", src.fetches["alpha"])
	}

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if src.fetchCount("alpha") != 1 {
		t.Errorf("second scan re-fetched alpha: total %d fetches, want 1", src.fetchCount("alpha"))
	}
	if res.Metrics.Fetched != 0 {
		t.Errorf("fetched = %d, want 0 when the listing is unchanged", res.Metrics.Fetched)
	}
	if res.Metrics.ListingOnly != 2 {
		t.Errorf("listing_only = %d, want 2", res.Metrics.ListingOnly)
	}
	if res.Metrics.Eligible != 2 {
		t.Errorf("eligible = %d, want the cheap tier to preserve eligibility", res.Metrics.Eligible)
	}
}

// TestListingChangeTriggersDetailFetch verifies a listing difference causes a
// re-read. This is how a material change is found without polling every detail
// page on every scan.
func TestListingChangeTriggersDetailFetch(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	// A real bounty increase shows up in both places: the listing the cheap tier
	// sees, and the detail record the expensive tier confirms. Changing only the
	// listing would mean the two disagreed, which is a different scenario.
	rec := src.records["alpha"]
	rec.MaxBountyRaw = "50000.0"
	src.records["alpha"] = rec
	src.refs[0].Listing.RewardRaw = "$50,000"

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if src.fetchCount("alpha") != 2 {
		t.Errorf("fetches = %d, want 2 after a listing change", src.fetchCount("alpha"))
	}
	if !hasChange(res) {
		t.Error("a bounty increase did not produce a detected change")
	}
	var sawBountyChange bool
	for _, e := range res.Programs {
		if e.Diff.Changes.Contains(domain.ChangeBountyChanged) {
			sawBountyChange = true
		}
	}
	if !sawBountyChange {
		t.Error("the change set does not include BOUNTY_CHANGED")
	}
}

// TestListingOnlyDifferenceDoesNotClaimChange verifies that when the listing
// disagrees with the detail record, the system reports what it actually read
// rather than inventing a change.
func TestListingOnlyDifferenceDoesNotClaimChange(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	// The listing moves but the detail record does not.
	src.refs[0].Listing.RewardRaw = "$50,000"

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if src.fetchCount("alpha") != 2 {
		t.Errorf("fetches = %d, want 2 so the detail record is checked", src.fetchCount("alpha"))
	}
	if hasChange(res) {
		t.Error("a change was claimed although the detail record was unchanged")
	}
}

// TestUnchangedDataDoesNotChurnState verifies a steady scan does not rewrite
// program content, which would create pointless diffs in version control.
func TestUnchangedDataDoesNotChurnState(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	first := readProgramsFile(t, dir)
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}
	second := readProgramsFile(t, dir)

	if stripVolatile(first) != stripVolatile(second) {
		t.Error("a steady-state scan rewrote program content")
	}
}

// TestParseFailureIsNotTreatedAsNoRequirements is the central safety property:
// an unreadable record must never look like a program with no gates.
func TestParseFailureIsNotTreatedAsNoRequirements(t *testing.T) {
	src := newFakeSource("alpha")
	src.failOn["alpha"] = fmt.Errorf("wrapped: %w", source.ErrParse)
	dir := t.TempDir()

	res, _ := runScanner(t, src, dir)

	snap, err := state.NewFileStore(dir).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Programs) != 0 {
		t.Errorf("a program that could not be parsed was stored: %d records", len(snap.Programs))
	}
	for _, a := range res.Alerts {
		if a.Decision.Eligible {
			t.Errorf("an alert was raised for an unreadable program: %s", a.Subject)
		}
	}
	if res.Metrics.FetchFailed != 1 {
		t.Errorf("fetch_failed = %d, want 1", res.Metrics.FetchFailed)
	}
}

// TestOneProgramFailingDoesNotEndTheScan verifies fault isolation.
func TestOneProgramFailingDoesNotEndTheScan(t *testing.T) {
	src := newFakeSource("alpha", "beta", "gamma")
	src.failOn["beta"] = errors.New("connection reset")
	dir := t.TempDir()

	res, _ := runScanner(t, src, dir)
	if res.Metrics.Discovered != 3 {
		t.Errorf("discovered = %d, want 3", res.Metrics.Discovered)
	}
	if res.Metrics.Eligible != 2 {
		t.Errorf("eligible = %d, want the two healthy programs", res.Metrics.Eligible)
	}
	if res.Metrics.Errors == 0 {
		t.Error("the failure was not reported")
	}
}

// TestSourceFailureIsContained verifies a failing source does not produce a
// false "nothing to report".
func TestSourceFailureIsContained(t *testing.T) {
	src := newFakeSource()
	src.discoverErr = fmt.Errorf("upstream down: %w", source.ErrUnavailable)
	dir := t.TempDir()

	res, err := runScanner(t, src, dir)
	if err == nil {
		t.Error("a total source failure reported success")
	}
	if res.Metrics.Discovered != 0 {
		t.Errorf("discovered = %d, want 0", res.Metrics.Discovered)
	}
	degraded, why := res.Metrics.Degraded()
	if !degraded {
		t.Error("a run that discovered nothing was not reported as degraded")
	}
	if !strings.Contains(why, "discovered") {
		t.Errorf("degraded reason = %q, want it to mention discovery", why)
	}
}

// TestNotificationFailureDoesNotLoseState verifies a delivery outage does not
// discard the scan or the alert.
func TestNotificationFailureDoesNotLoseState(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{err: errors.New("smtp unavailable")}

	res, err := runScanner(t, src, dir, func(c *pipeline.Config) { c.Notifier = notifier })
	if err == nil {
		t.Error("a delivery failure reported success")
	}
	if res.Metrics.AlertsFailed != 1 {
		t.Errorf("alerts_failed = %d, want 1", res.Metrics.AlertsFailed)
	}
	if res.Metrics.AlertsSent != 0 {
		t.Errorf("alerts_sent = %d, want 0", res.Metrics.AlertsSent)
	}

	// The alert must still be recorded so a later run can retry it.
	store := state.NewFileStore(dir)
	pending, err := store.ListAlerts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("recorded alerts = %d, want 1", len(pending))
	}
	if pending[0].Delivered {
		t.Error("a failed delivery was recorded as delivered")
	}
}

// TestDeliveryBookkeepingFailureMakesScanFail verifies a successful send whose
// delivered marker could not be persisted is visible in the scan result.
func TestDeliveryBookkeepingFailureMakesScanFail(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{}
	bookErr := errors.New("could not persist delivered marker")

	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Store = failingDeliveryStore{StateStore: state.NewFileStore(dir), err: bookErr}
		c.Notifier = notifier
	})
	if err == nil {
		t.Fatal("scan reported success despite a delivery-bookkeeping failure")
	}
	if res.Metrics.AlertsSent != 1 || res.Metrics.AlertsFailed != 0 {
		t.Errorf("sent=%d failed=%d, want sent=1 and failed=0", res.Metrics.AlertsSent, res.Metrics.AlertsFailed)
	}
	if len(notifier.delivered) != 1 {
		t.Errorf("notifier sent %d alerts, want one", len(notifier.delivered))
	}

	records, loadErr := state.NewFileStore(dir).ListAlerts(context.Background(), 0)
	if loadErr != nil {
		t.Fatalf("ListAlerts: %v", loadErr)
	}
	if len(records) != 1 || records[0].Delivered {
		t.Errorf("delivery records = %+v, want one pending alert for safe retry", records)
	}
}

// TestDryRunRecordsWithoutSending verifies a dry run produces alerts without
// transmitting them.
func TestDryRunRecordsWithoutSending(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{}

	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Notifier = notifier
		c.DryRun = true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) != 1 {
		t.Errorf("alerts generated = %d, want 1", len(res.Alerts))
	}
	if len(notifier.delivered) != 0 {
		t.Errorf("a dry run sent %d alerts", len(notifier.delivered))
	}
}

// TestDeliveredAlertIsNotResent verifies idempotency across runs.
func TestDeliveredAlertIsNotResent(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{}

	// First run alerts.
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) { c.Notifier = notifier })
	if err != nil {
		t.Fatal(err)
	}
	if len(notifier.delivered) != 1 {
		t.Fatalf("delivered = %d, want 1", len(notifier.delivered))
	}

	// Force a re-evaluation by dropping the stored program while keeping the
	// alert record, which is what a retry after a crash looks like.
	store := state.NewFileStore(dir)
	snap, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delete(snap.Programs, "fake:alpha")
	if err := store.Save(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	if _, err := runScanner(t, src, dir, func(c *pipeline.Config) { c.Notifier = notifier }); err != nil {
		t.Fatal(err)
	}
	if len(notifier.delivered) != 1 {
		t.Errorf("delivered = %d, want 1; an already-sent alert must not repeat", len(notifier.delivered))
	}
	_ = res
}

// TestNewlyEligibleAlerts verifies a program that becomes reachable alerts.
func TestNewlyEligibleAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	// Start with a reputation gate the profile cannot meet.
	rec := src.records["alpha"]
	rec.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 500}
	src.records["alpha"] = rec

	first, _ := runScanner(t, src, dir)
	if first.Metrics.Eligible != 0 {
		t.Fatalf("a 500-point program was eligible; fixture is wrong")
	}

	// The organization lowers the requirement.
	rec.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 20}
	src.records["alpha"] = rec
	src.refs[0].Listing.RewardRaw = "$5,500"

	second, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if second.Metrics.Eligible != 1 {
		t.Fatalf("eligible = %d, want 1 after the requirement dropped", second.Metrics.Eligible)
	}
	var found bool
	for _, a := range second.Alerts {
		if a.Kind == domain.AlertNewlyEligible {
			found = true
		}
	}
	if !found {
		var kinds []string
		for _, a := range second.Alerts {
			kinds = append(kinds, string(a.Kind))
		}
		t.Errorf("alerts = %v, want NEWLY_ELIGIBLE", kinds)
	}
}

// TestScopeExpansionAlerts verifies a new API in scope is reported.
func TestScopeExpansionAlerts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	rec := src.records["alpha"]
	rec.Scopes = append(rec.Scopes, domain.RawScope{Title: "API", Target: "https://api-v2.alpha.example.com"})
	src.records["alpha"] = rec
	src.refs[0].Listing.RewardRaw = "$5,001"

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) == 0 {
		t.Fatal("a new API target produced no alert")
	}
	if !res.Alerts[0].Changes.Contains(domain.ChangeAPIAdded) {
		t.Errorf("changes = %v, want API_ADDED", res.Alerts[0].Changes.Kinds())
	}
	if !strings.Contains(res.Alerts[0].Body, "api-v2.alpha.example.com") {
		t.Error("the alert does not name the new asset")
	}
}

// TestQuarantineDoesNotAlert verifies a poorly parsed record is silent.
func TestQuarantineDoesNotAlert(t *testing.T) {
	src := newFakeSource("alpha")
	rec := src.records["alpha"]
	rec.KYC = domain.TriUnknown
	rec.Fee = domain.FeeGate{Present: domain.TriUnknown}
	src.records["alpha"] = rec
	dir := t.TempDir()

	res, _ := runScanner(t, src, dir)
	if len(res.Alerts) != 0 {
		t.Errorf("a quarantined program alerted: %q", res.Alerts[0].Subject)
	}
	if res.Metrics.Quarantined != 1 {
		t.Errorf("quarantined = %d, want 1", res.Metrics.Quarantined)
	}
}

// TestDeterminismAcrossRuns verifies two identical scans produce identical
// results, which is what makes an eligibility claim reproducible.
func TestDeterminismAcrossRuns(t *testing.T) {
	build := func() pipeline.Result {
		src := newFakeSource("alpha", "beta")
		res, _ := runScanner(t, src, t.TempDir())
		return res
	}
	first := build()
	second := build()

	if len(first.Programs) != len(second.Programs) {
		t.Fatalf("program counts differ: %d vs %d", len(first.Programs), len(second.Programs))
	}
	for i := range first.Programs {
		if first.Programs[i].Program.ID != second.Programs[i].Program.ID {
			t.Fatalf("ordering differs at %d", i)
		}
		a, b := first.Programs[i], second.Programs[i]
		if a.Triage.Total != b.Triage.Total {
			t.Errorf("%s: triage %d vs %d", a.Program.ID, a.Triage.Total, b.Triage.Total)
		}
		if strings.Join(a.Decision.Reasons, "\n") != strings.Join(b.Decision.Reasons, "\n") {
			t.Errorf("%s: reasons differ", a.Program.ID)
		}
		if a.Program.ScopeFingerprint != b.Program.ScopeFingerprint {
			t.Errorf("%s: scope fingerprint differs", a.Program.ID)
		}
	}
	for i := range first.Alerts {
		if first.Alerts[i].Fingerprint != second.Alerts[i].Fingerprint {
			t.Errorf("alert fingerprint differs at %d", i)
		}
		if first.Alerts[i].Subject != second.Alerts[i].Subject {
			t.Errorf("alert subject differs at %d", i)
		}
		if first.Alerts[i].Body != second.Alerts[i].Body {
			t.Errorf("alert body differs at %d", i)
		}
	}
}

// TestQueryExplainsStoredPrograms verifies the query surface recomputes a
// decision consistent with the scan.
func TestQueryExplainsStoredPrograms(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	scanRes, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}

	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time { return fixedNow })
	rows, err := q.Programs(context.Background(), pipeline.ProgramRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("query returned %d programs, want 1", len(rows))
	}
	if !rows[0].Decision.Eligible {
		t.Error("a program the scan accepted was rejected by the query")
	}
	if scanRes.Metrics.Eligible != 1 {
		t.Errorf("scan eligible = %d, want 1", scanRes.Metrics.Eligible)
	}
}

// TestQueryResolvesBySlug verifies a bare slug finds its program.
func TestQueryResolvesBySlug(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}
	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time { return fixedNow })

	if _, ok, err := q.Explain(context.Background(), "alpha"); err != nil || !ok {
		t.Errorf("Explain(alpha) ok=%v err=%v, want a match", ok, err)
	}
	if _, ok, err := q.Explain(context.Background(), "missing"); err == nil || ok {
		t.Errorf("Explain(missing) ok=%v err=%v, want no match", ok, err)
	}
}

// TestNotifierInterfaceIsUsable verifies the notifier contract is satisfied by
// the test double through the real interface.
func TestNotifierInterfaceIsUsable(t *testing.T) {
	var n notify.Notifier = &recordingNotifier{}
	if !n.Configured() || n.Name() != "recording" {
		t.Error("the notifier contract is not satisfied")
	}
}

// readProgramsFile returns the raw programs state file.
func readProgramsFile(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "programs.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	return string(body)
}

// stripVolatile removes the fields that legitimately change on every scan, so
// that the comparison is about program content rather than timestamps.
func stripVolatile(in string) string {
	var b strings.Builder
	for _, line := range strings.Split(in, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, `"last_seen_at"`),
			strings.HasPrefix(trimmed, `"last_scan_id"`),
			strings.HasPrefix(trimmed, `"last_scan_at"`),
			strings.HasPrefix(trimmed, `"details_fetched_at"`),
			trimmed == `"listing": {`:
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// hasChange reports whether any evaluated program showed a change.
func hasChange(r pipeline.Result) bool {
	for _, e := range r.Programs {
		if !e.Diff.IsNew && !e.Diff.Changes.Empty() {
			return true
		}
	}
	return false
}

// TestDryRunRecordsAlertsForPreview verifies a dry run makes its alerts visible.
//
// A dry run that recorded nothing would be invisible in `hunter alerts` and
// would force a second scan to rediscover the same conditions. Recording them
// undelivered gives a preview, and lets a later live run deliver exactly those
// alerts because their fingerprints are unchanged.
func TestDryRunRecordsAlertsForPreview(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{}

	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Notifier = notifier
		c.DryRun = true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts generated = %d, want 1", len(res.Alerts))
	}

	records, err := state.NewFileStore(dir).ListAlerts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("recorded alerts = %d, want 1 so a dry run is inspectable", len(records))
	}
	if records[0].Delivered {
		t.Error("a dry run marked its alert delivered")
	}
	if records[0].Subject == "" {
		t.Error("the recorded alert has no subject")
	}
}

// TestDryRunThenLiveRunDeliversTheSameAlert verifies a previewed alert is
// delivered on the next live run.
//
// A scan only generates alerts for new conditions, so an alert created by a dry
// run would otherwise never be sent: by the time delivery is enabled the
// condition is no longer new. Reconstructing pending alerts from their records is
// what closes that gap.
func TestDryRunThenLiveRunDeliversTheSameAlert(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	notifier := &recordingNotifier{}

	// Dry run: records but does not send.
	if _, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Notifier = notifier
		c.DryRun = true
	}); err != nil {
		t.Fatal(err)
	}
	if len(notifier.delivered) != 0 {
		t.Fatal("a dry run sent an alert")
	}
	pending, err := state.NewFileStore(dir).ListAlerts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Delivered {
		t.Fatalf("pending alerts = %+v, want exactly one undelivered record", pending)
	}

	// Live run: no new condition exists, so the alert must come from the
	// recorded backlog.
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) { c.Notifier = notifier })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) != 0 {
		t.Errorf("generated %d new alerts, want 0 since nothing changed", len(res.Alerts))
	}
	if len(notifier.delivered) != 1 {
		t.Fatalf("delivered = %d, want the previewed alert to be sent on the live run", len(notifier.delivered))
	}
	if notifier.delivered[0].Subject != pending[0].Subject {
		t.Errorf("delivered subject %q, want the recorded one %q",
			notifier.delivered[0].Subject, pending[0].Subject)
	}
	if notifier.delivered[0].Body == "" {
		t.Error("the redelivered alert has no body")
	}

	after, err := state.NewFileStore(dir).ListAlerts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || !after[0].Delivered {
		t.Error("the alert was not marked delivered after successful redelivery")
	}

	// A third run must not send it again.
	if _, err := runScanner(t, src, dir, func(c *pipeline.Config) { c.Notifier = notifier }); err != nil {
		t.Fatal(err)
	}
	if len(notifier.delivered) != 1 {
		t.Errorf("delivered = %d after a third run, want 1; delivery must stay idempotent",
			len(notifier.delivered))
	}
}

// TestChangedMetricMatchesTheChangedQuery verifies the reported change count and
// the "programs --changed" filter agree.
//
// They once disagreed: the metric counted every observed difference while the
// filter listed only material ones, so a scan reporting "changed=4" listed
// nothing. A metric that disagrees with the command that queries it is worse than
// no metric at all.
func TestChangedMetricMatchesTheChangedQuery(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	// A moving submission count is a low-severity observation.
	src.refs[0].Listing.SubmittedReportsKnown = true
	n := 99
	src.refs[0].Listing.SubmittedReports = &n

	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}

	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time { return fixedNow })
	rows, err := q.Programs(context.Background(), pipeline.ProgramRequest{Changed: true})
	if err != nil {
		t.Fatal(err)
	}

	if res.Metrics.Changed != len(rows) {
		t.Errorf("scan reported changed=%d but the query listed %d",
			res.Metrics.Changed, len(rows))
	}
	if res.Metrics.Changed != 0 {
		t.Errorf("changed = %d, want 0; a submission count is not a material change", res.Metrics.Changed)
	}
	if res.Metrics.MinorChanged != 1 {
		t.Errorf("minor_changed = %d, want 1", res.Metrics.MinorChanged)
	}
}

// TestQueryWithNoFiltersReturnsEverything guards the base listing.
//
// A recency filter must be opt-in. When it was applied by default, every
// program on the platform was hidden and `hunter programs` reported nothing at
// all, which reads as "the monitor is broken" rather than "you filtered
// everything out".
func TestQueryWithNoFiltersReturnsEverything(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time { return fixedNow })

	all, err := q.Programs(context.Background(), pipeline.ProgramRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered listing returned %d programs, want 2", len(all))
	}

	eligible, err := q.Programs(context.Background(), pipeline.ProgramRequest{Eligible: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(eligible) == 0 {
		t.Error("the eligible listing is empty")
	}
}

// TestQueryLaunchWindowIsOptIn verifies the recency filter applies only when
// asked for, and then actually filters.
func TestQueryLaunchWindowIsOptIn(t *testing.T) {
	src := newFakeSource("alpha", "beta")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	q := pipeline.NewQuery(testProfile(t), state.NewFileStore(dir), func() time.Time { return fixedNow })

	// The fixtures were launched the same day, so a window that excludes them
	// must exclude them, and an absent filter must not.
	old := fixedNow.Add(-72 * time.Hour)
	snap, err := state.NewFileStore(dir).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range snap.Programs {
		p.StartedAt = &old
		snap.Programs[id] = p
	}
	if err := state.NewFileStore(dir).Save(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	all, err := q.Programs(context.Background(), pipeline.ProgramRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("unfiltered listing returned %d, want 2; the recency filter must be opt-in", len(all))
	}

	fresh, err := q.Programs(context.Background(), pipeline.ProgramRequest{LaunchWindow: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 0 {
		t.Errorf("a one-hour window returned %d programs that launched three days ago", len(fresh))
	}

	wide, err := q.Programs(context.Background(), pipeline.ProgramRequest{LaunchWindow: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(wide) != 2 {
		t.Errorf("a thirty-day window returned %d, want 2", len(wide))
	}
}
