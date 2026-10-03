package state_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/state"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *state.FileStore {
	t.Helper()
	return state.NewFileStore(t.TempDir())
}

func sampleProgram(id, slug string) domain.Program {
	max := 5000.0
	started := fixedNow.Add(-72 * time.Hour)
	p := domain.Program{
		ID:              id,
		Source:          "hackenproof",
		Slug:            slug,
		Name:            "Example " + slug,
		URL:             "https://example.test/programs/" + slug,
		State:           domain.StateLive,
		Reputation:      domain.ReputationGate{Present: domain.TriNo},
		Fee:             domain.FeeGate{Present: domain.TriNo},
		KYC:             domain.TriNo,
		POC:             domain.TriYes,
		MaxBountyUSD:    &max,
		SurfaceTags:     domain.NewTags("web_application", "api"),
		CryptoKind:      domain.CryptoPlatform,
		ParseConfidence: domain.ConfidenceHigh,
		StartedAt:       &started,
		FirstSeenAt:     fixedNow.Add(-24 * time.Hour),
		LastSeenAt:      fixedNow,
	}
	p.Finalize()
	return p
}

// TestLoadOnEmptyDirectory verifies a first run is not an error. Treating a
// missing snapshot as a failure would make the very first scheduled run look
// broken.
func TestLoadOnEmptyDirectory(t *testing.T) {
	s := newStore(t)
	snap, err := s.Load(context.Background())
	if err != nil {
		t.Fatalf("Load on empty directory: %v", err)
	}
	if len(snap.Programs) != 0 {
		t.Errorf("programs = %d, want 0", len(snap.Programs))
	}
	if snap.Version != state.CurrentVersion {
		t.Errorf("version = %d, want %d", snap.Version, state.CurrentVersion)
	}
}

// TestRoundTrip verifies programs and alerts survive a save and load.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := state.NewFileStore(dir)

	p := sampleProgram("hackenproof:alpha", "alpha")
	snap := state.NewSnapshot()
	snap.Programs[p.ID] = p
	snap.LastScanID = "20261001T120000Z"
	snap.LastScanAt = fixedNow
	snap.Alerts["abc123"] = domain.AlertRecord{
		Fingerprint: "abc123", Kind: domain.AlertNewQualifying,
		ProgramID: p.ID, ScanID: snap.LastScanID,
		CreatedAt: fixedNow, Delivered: true, DeliveredAt: fixedNow,
	}
	if err := s.Save(ctx, snap); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := state.NewFileStore(dir).Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := reloaded.Program(p.ID)
	if !ok {
		t.Fatalf("program %s missing after reload", p.ID)
	}
	if got.Name != p.Name || got.Slug != p.Slug {
		t.Errorf("program = %+v, want name %q slug %q", got, p.Name, p.Slug)
	}
	if got.KYC != p.KYC || got.Fee.Present != p.Fee.Present {
		t.Errorf("access facts lost: KYC=%s fee=%s", got.KYC, got.Fee.Present)
	}
	if got.ScopeFingerprint != p.ScopeFingerprint {
		t.Errorf("scope fingerprint changed across save/load:\n got %s\nwant %s",
			got.ScopeFingerprint, p.ScopeFingerprint)
	}
	if reloaded.LastScanID != snap.LastScanID {
		t.Errorf("LastScanID = %q, want %q", reloaded.LastScanID, snap.LastScanID)
	}
	if !reloaded.AlertDelivered("abc123") {
		t.Error("delivered alert not recorded after reload")
	}
}

// TestWritesAreDeterministic is the property that keeps version-controlled
// state reviewable: a run that changed nothing must not produce a diff.
func TestWritesAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := state.NewFileStore(dir)

	build := func() *state.Snapshot {
		snap := state.NewSnapshot()
		// Insert in a deliberately unstable order to prove that serialization
		// does not depend on insertion order.
		for _, id := range []string{"hackenproof:zeta", "hackenproof:alpha", "hackenproof:mid"} {
			slug := strings.SplitN(id, ":", 2)[1]
			snap.Programs[id] = sampleProgram(id, slug)
		}
		return snap
	}

	if err := s.Save(ctx, build()); err != nil {
		t.Fatalf("first save: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "programs.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Save again from an identically constructed snapshot.
	if err := s.Save(ctx, build()); err != nil {
		t.Fatalf("second save: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "programs.json"))
	if err != nil {
		t.Fatal(err)
	}

	if string(first) != string(second) {
		t.Error("repeated saves produced different bytes; state would churn in version control")
	}
	if !strings.HasSuffix(string(first), "\n") {
		t.Error("state file does not end with a newline")
	}
}

// TestCorruptStateIsReported verifies damaged state is surfaced rather than
// discarded.
//
// Silently starting from an empty snapshot would make every known program look
// new and fire an alert for all of them. That failure mode is far worse than a
// clear error message.
func TestCorruptStateIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "programs.json")
	if err := os.WriteFile(path, []byte("{ this is not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := state.NewFileStore(dir).Load(context.Background())
	if err == nil {
		t.Fatal("corrupt state loaded without error")
	}
	if !errors.Is(err, state.ErrCorrupt) {
		t.Errorf("error = %v, want it to wrap ErrCorrupt", err)
	}
}

// TestFutureVersionIsRejected verifies a state file written by a newer build is
// refused rather than misread.
func TestFutureVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	body := `{"version":9999,"last_scan_id":"x","last_scan_at":"2026-01-01T00:00:00Z","programs":{}}`
	if err := os.WriteFile(filepath.Join(dir, "programs.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := state.NewFileStore(dir).Load(context.Background())
	if err == nil {
		t.Fatal("state from a future version loaded without error")
	}
	if !errors.Is(err, state.ErrCorrupt) {
		t.Errorf("error = %v, want it to wrap ErrCorrupt", err)
	}
}

// TestAlertAttemptLifecycle verifies the record-then-deliver sequence that
// makes retries safe.
func TestAlertAttemptLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	rec := domain.AlertRecord{
		Fingerprint: "fp1", Kind: domain.AlertNewQualifying,
		ProgramID: "hackenproof:alpha", ScanID: "scan1",
		CreatedAt: fixedNow, LastAttemptAt: fixedNow,
	}
	if err := s.RecordAlertAttempt(ctx, rec); err != nil {
		t.Fatalf("RecordAlertAttempt: %v", err)
	}

	got, err := s.AlertRecordFor(ctx, "fp1")
	if err != nil {
		t.Fatalf("AlertRecordFor: %v", err)
	}
	if got.Delivered {
		t.Error("alert marked delivered before delivery was attempted")
	}

	// A retry must accumulate attempts rather than overwrite the record.
	retry := rec
	retry.LastError = "smtp timeout"
	if err := s.RecordAlertAttempt(ctx, retry); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	got, err = s.AlertRecordFor(ctx, "fp1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Attempts < 2 {
		t.Errorf("attempts = %d, want at least 2 after a retry", got.Attempts)
	}
	if got.LastError != "smtp timeout" {
		t.Errorf("LastError = %q, want the failure reason retained", got.LastError)
	}

	if err := s.MarkAlertDelivered(ctx, "fp1", fixedNow.Add(time.Minute)); err != nil {
		t.Fatalf("MarkAlertDelivered: %v", err)
	}
	got, _ = s.AlertRecordFor(ctx, "fp1")
	if !got.Delivered || got.LastError != "" {
		t.Errorf("record after delivery = %+v, want delivered with the error cleared", got)
	}
}

// TestMarkUndeliveredAlertIsReported verifies an unknown fingerprint is an
// error rather than a silent success that would hide a logic bug.
func TestMarkUndeliveredAlertIsReported(t *testing.T) {
	err := newStore(t).MarkAlertDelivered(context.Background(), "nope", fixedNow)
	if !errors.Is(err, state.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// TestListAlertsPrioritizesUndelivered verifies failures surface first.
func TestListAlertsPrioritizesUndelivered(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// "a" is delivered and older; "b" failed and is newer.
	for _, fp := range []string{"a", "b"} {
		rec := domain.AlertRecord{
			Fingerprint: fp, ProgramID: "p", CreatedAt: fixedNow.Add(time.Hour),
		}
		if err := s.RecordAlertAttempt(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkAlertDelivered(ctx, "a", fixedNow); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListAlerts(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d alerts, want 2", len(list))
	}
	if list[0].Fingerprint != "b" {
		t.Errorf("first alert = %s, want the undelivered one", list[0].Fingerprint)
	}
}

// TestHistoryIsBoundedAndOrdered verifies history appends and stays within its
// cap, because it is committed to version control on every run.
func TestHistoryIsBoundedAndOrdered(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for i := 0; i < state.MaxHistoryPerProgram+25; i++ {
		entry := state.HistoryEntry{
			ScanID: "scan", At: fixedNow.Add(time.Duration(i) * time.Minute),
			Kinds: []string{"SCOPE_CHANGED"}, Eligible: true,
		}
		if err := s.AppendHistory(ctx, "hackenproof:alpha", entry); err != nil {
			t.Fatalf("AppendHistory %d: %v", i, err)
		}
	}

	got, err := s.HistoryFor(ctx, "hackenproof:alpha")
	if err != nil {
		t.Fatalf("HistoryFor: %v", err)
	}
	if len(got) != state.MaxHistoryPerProgram {
		t.Errorf("history length = %d, want it capped at %d", len(got), state.MaxHistoryPerProgram)
	}
	// The oldest entries must be the ones dropped.
	if got[0].At.After(got[1].At) {
		t.Error("history is not ordered oldest first")
	}
}

// TestHistoryIsolatesPrograms verifies per-program history does not leak.
func TestHistoryIsolatesPrograms(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.AppendHistory(ctx, "hackenproof:a", state.HistoryEntry{ScanID: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendHistory(ctx, "hackenproof:b", state.HistoryEntry{ScanID: "2"}); err != nil {
		t.Fatal(err)
	}

	a, err := s.HistoryFor(ctx, "hackenproof:a")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0].ScanID != "1" {
		t.Errorf("history for a = %+v, want one entry from scan 1", a)
	}

	missing, err := s.HistoryFor(ctx, "hackenproof:never-seen")
	if err != nil {
		t.Errorf("HistoryFor for an unknown program returned an error: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("history for an unknown program = %d entries, want 0", len(missing))
	}
}

// TestProgramIDCannotEscapeStateDirectory verifies a hostile identifier cannot
// write outside the state directory. The property that matters is containment,
// not the absence of dots: a program ID legitimately may contain dots.
func TestProgramIDCannotEscapeStateDirectory(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := state.NewFileStore(dir)

	historyDir := filepath.Join(dir, "history")
	for _, hostile := range []string{"../../escaped", "a/b/c", `..\..\win`, "..", "."} {
		if err := s.AppendHistory(ctx, hostile, state.HistoryEntry{ScanID: "x"}); err != nil {
			t.Fatalf("AppendHistory(%q): %v", hostile, err)
		}
	}

	entries, err := os.ReadDir(historyDir)
	if err != nil {
		t.Fatalf("history directory missing: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no history files were written")
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("history contains a directory %q", e.Name())
		}
		// Every entry must resolve inside the history directory.
		resolved, err := filepath.Abs(filepath.Join(historyDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		base, err := filepath.Abs(historyDir)
		if err != nil {
			t.Fatal(err)
		}
		if rel, err := filepath.Rel(base, resolved); err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("history entry %q resolves outside the state directory", e.Name())
		}
	}

	// Nothing may have been created above the state directory.
	if _, err := os.Stat(filepath.Join(dir, "..", "escaped.json")); err == nil {
		t.Error("a file was written outside the state directory")
	}
}

// TestContextCancellationIsHonoured verifies a cancelled scan does not keep
// writing state.
func TestContextCancellationIsHonoured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newStore(t)

	snap := state.NewSnapshot()
	if err := s.Save(ctx, snap); !errors.Is(err, context.Canceled) {
		t.Errorf("Save with a cancelled context = %v, want context.Canceled", err)
	}
	if _, err := s.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Load with a cancelled context = %v, want context.Canceled", err)
	}
}

// TestDescribeReportsBackend verifies diagnostics can identify the backend.
func TestDescribeReportsBackend(t *testing.T) {
	dir := t.TempDir()
	if got := state.NewFileStore(dir).Describe(); !strings.HasPrefix(got, "file:") {
		t.Errorf("Describe() = %q, want a file: prefix", got)
	}
}

// TestMaterialDigestIgnoresVolatileFields verifies a scan that learned nothing
// produces the same digest.
//
// This is what stops the scheduled workflow from committing on every run. A
// digest that moved on every scan would make the repository grow for no reason,
// and would bury the commits that actually record something.
func TestMaterialDigestIgnoresVolatileFields(t *testing.T) {
	build := func() *state.Snapshot {
		p := sampleProgram("hackenproof:alpha", "alpha")
		snap := state.NewSnapshot()
		snap.Programs[p.ID] = p
		snap.Alerts["fp1"] = domain.AlertRecord{
			Fingerprint: "fp1", Delivered: true, Kind: domain.AlertNewQualifying,
			Subject: "s", CreatedAt: fixedNow,
		}
		return snap
	}

	first := build().MaterialDigest()

	// Advance every volatile timestamp, as a later scan would.
	snap := build()
	p := snap.Programs["hackenproof:alpha"]
	p.LastSeenAt = fixedNow.Add(time.Hour)
	snap.Programs[p.ID] = p
	snap.LastScanID = "20261001T130000Z"
	snap.LastScanAt = fixedNow.Add(time.Hour)

	if snap.MaterialDigest() != first {
		t.Error("a scan that changed nothing moved the material digest")
	}
}

// TestMaterialDigestDetectsRealChange verifies the digest is not so insensitive
// that it ignores genuine change.
func TestMaterialDigestDetectsRealChange(t *testing.T) {
	baseline := func() *state.Snapshot {
		p := sampleProgram("hackenproof:alpha", "alpha")
		snap := state.NewSnapshot()
		snap.Programs[p.ID] = p
		return snap
	}
	first := baseline().MaterialDigest()

	t.Run("scope change", func(t *testing.T) {
		snap := baseline()
		p := snap.Programs["hackenproof:alpha"]
		p.ScopeFingerprint = "different"
		snap.Programs[p.ID] = p
		if snap.MaterialDigest() == first {
			t.Error("a scope change did not move the digest")
		}
	})

	t.Run("new program", func(t *testing.T) {
		snap := baseline()
		snap.Programs["hackenproof:beta"] = sampleProgram("hackenproof:beta", "beta")
		if snap.MaterialDigest() == first {
			t.Error("a new program did not move the digest")
		}
	})

	t.Run("program removed", func(t *testing.T) {
		snap := baseline()
		delete(snap.Programs, "hackenproof:alpha")
		if snap.MaterialDigest() == first {
			t.Error("a removed program did not move the digest")
		}
	})

	t.Run("alert recorded", func(t *testing.T) {
		snap := baseline()
		snap.Alerts["fp1"] = domain.AlertRecord{Fingerprint: "fp1"}
		if snap.MaterialDigest() == first {
			t.Error("a recorded alert did not move the digest")
		}
	})

	t.Run("alert delivery state", func(t *testing.T) {
		snap := baseline()
		snap.Alerts["fp1"] = domain.AlertRecord{Fingerprint: "fp1", Delivered: true}
		if snap.MaterialDigest() == first {
			t.Error("a delivery state change did not move the digest")
		}
	})
}

// TestMaterialDigestIsStableAcrossWrites verifies a saved snapshot reloads to
// the same digest, which is what makes it comparable in version control.
func TestMaterialDigestIsStableAcrossWrites(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := state.NewFileStore(dir)

	snap := state.NewSnapshot()
	snap.Programs["hackenproof:alpha"] = sampleProgram("hackenproof:alpha", "alpha")
	if err := s.Save(ctx, snap); err != nil {
		t.Fatal(err)
	}

	reloaded, err := state.NewFileStore(dir).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.MaterialDigest() != snap.MaterialDigest() {
		t.Error("digest changed across a save and load round trip")
	}
}

// TestSaveWritesDigestFile verifies the digest the workflow compares is written.
func TestSaveWritesDigestFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := state.NewFileStore(dir)

	snap := state.NewSnapshot()
	snap.Programs["hackenproof:alpha"] = sampleProgram("hackenproof:alpha", "alpha")
	if err := s.Save(ctx, snap); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "material.sha256"))
	if err != nil {
		t.Fatalf("digest file missing: %v", err)
	}
	got := strings.TrimSpace(string(raw))
	if len(got) != 64 {
		t.Errorf("digest file holds %q, want a 64-character hex digest", got)
	}
	if strings.ContainsAny(got, "\"\\") {
		t.Errorf("digest file looks JSON-encoded: %q", got)
	}
	if got != snap.MaterialDigest() {
		t.Errorf("digest file = %s, want %s", got, snap.MaterialDigest())
	}
}

// TestDeliveredAlertsArePruned verifies bounded growth of the alert store, and
// that an alert still owed to the researcher is never the one discarded.
func TestDeliveredAlertsArePruned(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := state.NewFileStore(dir)

	snap := state.NewSnapshot()
	base := fixedNow
	for i := 0; i < state.MaxDeliveredAlerts+50; i++ {
		fp := fmt.Sprintf("fp%05d", i)
		snap.Alerts[fp] = domain.AlertRecord{
			Fingerprint: fp,
			Delivered:   true,
			CreatedAt:   base.Add(time.Duration(i) * time.Second),
		}
	}
	// One alert still awaiting delivery must survive regardless of age.
	snap.Alerts["pending"] = domain.AlertRecord{
		Fingerprint: "pending", CreatedAt: base.Add(-time.Hour),
	}

	if err := s.Save(ctx, snap); err != nil {
		t.Fatal(err)
	}

	reloaded, err := state.NewFileStore(dir).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Alerts["pending"]; !ok {
		t.Fatal("an undelivered alert was pruned; the researcher would never receive it")
	}
	delivered := 0
	for _, rec := range reloaded.Alerts {
		if rec.Delivered {
			delivered++
		}
	}
	if delivered > state.MaxDeliveredAlerts {
		t.Errorf("retained %d delivered records, want at most %d", delivered, state.MaxDeliveredAlerts)
	}
	if len(reloaded.Alerts) > state.MaxDeliveredAlerts+1 {
		t.Errorf("retained %d records overall, want the cap plus the pending one",
			len(reloaded.Alerts))
	}
}
