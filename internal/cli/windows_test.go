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

func seedWindowState(t *testing.T, dir string, observed domain.ObservationInterval) {
	t.Helper()
	store := state.NewFileStore(dir)
	snap := state.NewSnapshot()
	snap.Programs["fake:alpha"] = domain.Program{
		ID: "fake:alpha", Source: "fake", Slug: "alpha", Name: "Alpha Program",
	}
	baseline, current, movement := 12, 15, 3
	window := domain.NewOpportunityWindow("fake:alpha", "Alpha Program", observed, domain.Deltas{
		{
			Field: "scope", Kind: domain.ChangeAPIAdded,
			Before: "no API target", After: "api.example.test",
			Direction: domain.DirectionImproved,
			Assets:    []string{"api.example.test"},
		},
		{
			Field: "kyc", Kind: domain.ChangeKYCRemoved,
			Before: "required", After: "not required",
			Direction: domain.DirectionImproved,
		},
	}, domain.OpportunityWindowOptions{ScanID: "scan-one"})
	window.BaselineSubmissions = &baseline
	window.CurrentSubmissions = &current
	window.SubmissionsSinceOpen = &movement
	snap.RecordWindow(window)
	if err := store.Save(context.Background(), snap); err != nil {
		t.Fatalf("save state: %v", err)
	}
}

func runWindowsCommand(t *testing.T, dir string, now time.Time, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cliArgs := append([]string{"windows", "--profile", "../../configs/profiles/personal.yaml", "--state", dir}, args...)
	env := &cli.Env{
		Stdout: &stdout, Stderr: &stderr, Args: cliArgs,
		Now:       func() time.Time { return now },
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	code := cli.Run(context.Background(), env)
	return code, stdout.String(), stderr.String()
}

func TestWindowsCommandRendersAtomicEvidenceAndStatus(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedWindowState(t, dir, domain.NewObservationInterval(base, base.Add(time.Minute)))

	code, stdout, stderr := runWindowsCommand(t, dir, base.Add(2*time.Minute))
	if code != 0 {
		t.Fatalf("windows exit = %d; stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"RESEARCH WINDOW", "[OPEN]", "Alpha Program", "Observed: within the last",
		"API_ADDED", "KYC_REMOVED", "baseline 12; current 15; change +3",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("windows output is missing %q:\n%s", want, stdout)
		}
	}
}

func TestWindowsCommandSupportsOpenAndJSONFilters(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedWindowState(t, dir, domain.NewObservationInterval(base, base.Add(time.Minute)))

	code, stdout, stderr := runWindowsCommand(t, dir, base.Add(2*time.Minute),
		"--open", "--program", "alpha", "--json")
	if code != 0 {
		t.Fatalf("windows --json exit = %d; stderr: %s", code, stderr)
	}
	for _, want := range []string{`"count": 1`, `"status": "open"`, `"kind": "API_ADDED"`, `"kind": "KYC_REMOVED"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("JSON output is missing %q:\n%s", want, stdout)
		}
	}
}
