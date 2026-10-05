package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/cli"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/state"
)

func seedReplayState(t *testing.T, dir string, base time.Time) {
	t.Helper()
	store := state.NewFileStore(dir)
	snap := state.NewSnapshot()
	programID := "fake:alpha"
	snap.Programs[programID] = domain.Program{
		ID: programID, Source: "fake", Slug: "alpha", Name: "Alpha Program",
	}

	baseline, current, movement := 12, 15, 3
	opened := domain.NewOpportunityWindow(programID, "Alpha Program",
		domain.NewObservationInterval(base, base.Add(time.Minute)),
		domain.Deltas{{
			Field: "kyc", Kind: domain.ChangeKYCRemoved,
			Before: "required", After: "not required",
			Direction: domain.DirectionImproved,
		}}, domain.OpportunityWindowOptions{ScanID: "scan-one"})
	opened.BaselineSubmissions = &baseline
	opened.CurrentSubmissions = &current
	opened.SubmissionsSinceOpen = &movement
	snap.RecordWindow(opened)

	unmatched := domain.NewOpportunityWindow(programID, "Alpha Program",
		domain.NewObservationInterval(base.Add(time.Hour), base.Add(time.Hour+time.Minute)),
		domain.Deltas{{
			Field: "scope", Kind: domain.ChangeAPIAdded,
			After: "api.example.test", Direction: domain.DirectionImproved,
		}}, domain.OpportunityWindowOptions{ScanID: "scan-two"})
	snap.RecordWindow(unmatched)

	if err := store.Save(context.Background(), snap); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if err := store.AppendHistory(context.Background(), programID, state.HistoryEntry{
		ScanID: "scan-one", At: base.Add(2 * time.Minute),
		Changes: domain.ChangeSet{{
			Kind: domain.ChangeKYCRemoved, Severity: domain.SeverityMedium,
			Field: "kyc", Before: "required", After: "not required",
			Direction: domain.DirectionImproved,
		}},
		Eligible: true, Reasons: []string{"all access requirements passed"},
	}); err != nil {
		t.Fatalf("append history: %v", err)
	}
}

func runReplayCommand(t *testing.T, dir string, now time.Time, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cliArgs := append([]string{"replay", "--profile", "../../configs/profiles/personal.yaml", "--state", dir}, args...)
	env := &cli.Env{
		Stdout: &stdout, Stderr: &stderr, Args: cliArgs,
		Now:       func() time.Time { return now },
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	code := cli.Run(context.Background(), env)
	return code, stdout.String(), stderr.String()
}

func TestReplayMergesHistoryAndWindowsAsRecordedEvidence(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedReplayState(t, dir, base)

	code, stdout, stderr := runReplayCommand(t, dir, base.Add(2*time.Hour), "alpha")
	if code != 0 {
		t.Fatalf("replay exit = %d; stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"Saved timeline for fake:alpha (2 of 2 event(s)",
		"EVENT 1 [CHANGE_AND_WINDOW]", "Recorded at:", "Eligibility recorded: true",
		"reason: all access requirements passed", "Opportunity window", "Observed interval:",
		"KYC_REMOVED", "baseline 12; current 15; change +3", "EVENT 2 [OPPORTUNITY_WINDOW]",
		"past decisions are not re-evaluated",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("replay output is missing %q:\n%s", want, stdout)
		}
	}
}

func TestReplayJSONReportsLimitAndTotal(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedReplayState(t, dir, base)

	code, stdout, stderr := runReplayCommand(t, dir, base.Add(2*time.Hour), "--json", "--limit", "1", "alpha")
	if code != 0 {
		t.Fatalf("replay --json exit = %d; stderr: %s", code, stderr)
	}
	for _, want := range []string{`"program_id": "fake:alpha"`, `"count": 1`, `"total": 2`, `"kind": "change_and_window"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("JSON output is missing %q:\n%s", want, stdout)
		}
	}
}
