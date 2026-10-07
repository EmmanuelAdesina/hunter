package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/cli"
)

// A scan whose state cannot be loaded must say so loudly. The degraded check
// fires on any empty result, so without an explicit error line a load failure
// presents as a completed scan that merely found nothing - which once cost
// real debugging time against a corrupt state file, with the actual error
// silently dropped.
func TestScanSurfacesLoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "programs.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	env := &cli.Env{
		Stdout: &stdout, Stderr: &stderr,
		Args: []string{"scan", "--dry-run",
			"--profile", "../../configs/profiles/personal.yaml",
			"--state", dir},
		Now:       func() time.Time { return time.Now() },
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	code := cli.Run(context.Background(), env)

	if code != 3 {
		t.Errorf("scan exit = %d, want 3 (degraded: nothing could be evaluated)", code)
	}
	if got := stderr.String(); !strings.Contains(got, "scan error:") || !strings.Contains(got, "load state") {
		t.Errorf("stderr does not report the load failure:\n%s", got)
	}
}
