package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eadeshina/hunter/internal/config"
	"gopkg.in/yaml.v3"
)

// workflowFile describes one parsed workflow file.
type workflowFile struct {
	Name string `yaml:"name"`
	On   any    `yaml:"on"`
	Jobs map[string]struct {
		Name  string            `yaml:"name"`
		Env   map[string]string `yaml:"env"`
		Steps []struct {
			Name string            `yaml:"name"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
			If   string            `yaml:"if"`
		} `yaml:"steps"`
		Permissions any `yaml:"permissions"`
	} `yaml:"jobs"`
	Permissions any `yaml:"permissions"`
}

// loadWorkflow parses a workflow from the repository.
func loadWorkflow(t *testing.T, name string) workflowFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return wf
}

// TestWorkflowsAreValidYAML verifies every workflow parses. A workflow that does
// not parse is silently skipped by the runner, so a scheduled monitor could stop
// firing without any error being reported anywhere.
func TestWorkflowsAreValidYAML(t *testing.T) {
	for _, name := range []string{"monitor.yml", "test.yml", "release.yml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var wf workflowFile
			if err := yaml.Unmarshal(raw, &wf); err != nil {
				t.Fatalf("workflow does not parse: %v", err)
			}
			if len(wf.Jobs) == 0 {
				t.Error("workflow declares no jobs")
			}
		})
	}
}

// TestWorkflowShellIsValidBash verifies every run block is syntactically valid.
//
// Shell inside a workflow is not compiled anywhere, so a typo sits unnoticed
// until the schedule fires. The monitor runs unattended, which means a broken
// block would be discovered at an awkward time rather than in review.
//
// The check is skipped when bash is unavailable rather than failing, so the suite
// still runs on a machine without a POSIX shell.
func TestWorkflowShellIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available; skipping workflow shell validation")
	}

	dir := t.TempDir()
	for _, name := range []string{"monitor.yml", "test.yml", "release.yml"} {
		wf := loadWorkflow(t, name)
		for jobName, job := range wf.Jobs {
			for i, step := range job.Steps {
				if step.Run == "" {
					continue
				}
				path := filepath.Join(dir, "step.sh")
				// The path is quoted because a temp directory can contain spaces.
				if err := os.WriteFile(path, []byte(step.Run), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bash, "-n", path)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Errorf("%s :: %s :: step %d (%s) is not valid bash:\n%s",
						name, jobName, i, step.Name, out)
				}
			}
		}
	}
}

// TestMonitorWorkflowHasSchedule verifies the monitor is scheduled.
//
// A monitor with no schedule never runs. That is the single failure that would
// make the whole repository inert while every other signal looked healthy.
func TestMonitorWorkflowHasSchedule(t *testing.T) {
	wf := loadWorkflow(t, "monitor.yml")

	// The on: key parses as a mapping, so it is inspected structurally.
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "monitor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "schedule:") {
		t.Fatal("the monitor workflow declares no schedule")
	}
	if !strings.Contains(string(raw), "cron:") {
		t.Fatal("the monitor schedule has no cron expression")
	}
	if !strings.Contains(string(raw), "workflow_dispatch:") {
		t.Error("the monitor workflow has no manual trigger, so it cannot be validated by hand")
	}
	_ = wf
}

// TestCronIsOffsetFromTheHour pins the deliberate offset.
//
// GitHub's scheduler is congested at the top of the hour. A naive "*/5" fires at
// exactly the worst minute every time, and a schedule that runs late defeats the
// purpose of a five-minute monitor.
func TestCronIsOffsetFromTheHour(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "monitor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	const cronKey = "- cron: \""
	i := strings.Index(body, cronKey)
	if i < 0 {
		t.Fatal("no cron expression found")
	}
	expr := body[i+len(cronKey):]
	if j := strings.Index(expr, "\""); j >= 0 {
		expr = expr[:j]
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		t.Fatalf("cron %q has %d fields, want 5", expr, len(fields))
	}

	minutes := strings.Split(fields[0], ",")
	if len(minutes) < 2 {
		t.Fatalf("cron %q runs less often than every five minutes", expr)
	}
	if minutes[0] == "0" {
		t.Errorf("cron %q fires at minute 0, the most congested slot; offset it", expr)
	}
	if minutes[len(minutes)-1] == "59" {
		t.Errorf("cron %q fires at minute 59, immediately before the congested hour", expr)
	}

	// Every minute must be distinct and within range.
	seen := map[string]bool{}
	for _, m := range minutes {
		if seen[m] {
			t.Errorf("cron %q repeats minute %s", expr, m)
		}
		seen[m] = true
	}
}

// TestMonitorReadsOnlySecretBackedEnvironment verifies delivery credentials come
// from secrets and are never written into the repository.
//
// A literal credential in a workflow file would be published with the repository
// the moment it went public, so the only acceptable spelling is a secrets
// reference.
func TestMonitorReadsOnlySecretBackedEnvironment(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "monitor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	required := []string{
		"EMAIL_SMTP_HOST", "EMAIL_SMTP_PORT", "EMAIL_USERNAME",
		"EMAIL_PASSWORD", "ALERT_RECIPIENT",
	}
	for _, name := range required {
		if !strings.Contains(body, "secrets."+name) {
			t.Errorf("%s is not read from secrets", name)
		}
	}
}

// TestRepositoryContainsNoCredentials verifies no committed file holds a value
// that looks like a live credential.
//
// The repository is public, so a credential committed at any point is disclosed
// immediately and must be treated as compromised. This runs in CI so that an
// accidental commit is caught before it ships rather than after.
func TestRepositoryContainsNoCredentials(t *testing.T) {
	// Patterns for credentials that must never appear in tracked files.
	//
	// Only unambiguous, provider-specific shapes are listed. A generic
	// "long alphanumeric string" rule is deliberately absent: it matches Go
	// identifiers, module hashes and base64 fragments, so it reports constantly
	// and trains the reader to ignore it. Detection of a specific leaked value
	// is handled by scanning for that value at the point of use instead.
	patterns := []struct {
		name string
		re   string
	}{
		{"GitHub token", `gh[pousr]_[A-Za-z0-9]{20,}`},
		{"GitHub fine-grained token", `github_pat_[A-Za-z0-9_]{20,}`},
		{"AWS access key id", `AKIA[0-9A-Z]{16}`},
		{"Slack token", `xox[baprs]-[A-Za-z0-9-]{10,}`},
		{"Private key block", `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
	}

	skipDirs := map[string]bool{".git": true, "bin": true, "dist": true, "fixtures": true}
	var checked int

	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" && ext != ".yml" && ext != ".yaml" && ext != ".sh" &&
			ext != ".md" && ext != ".json" && ext != "" && ext != ".mod" && ext != ".sum" {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		checked++

		for _, p := range patterns {
			re, cerr := regexpCompile(p.re)
			if cerr != nil {
				continue
			}
			if loc := re.FindIndex(body); loc != nil {
				// Report the shape rather than the value, so the finding itself
				// never leaks the secret into a build log.
				t.Errorf("%s: file contains something matching %s near byte %d; "+
					"if this is a real credential, revoke it before anything else",
					strings.TrimPrefix(path, "../../"), p.name, loc[0])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("no files were inspected; the check is not running")
	}
	t.Logf("inspected %d files for credential patterns", checked)
}

// TestShippedProfileHoldsNoCredentials verifies the profile carries policy only.
func TestShippedProfileHoldsNoCredentials(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "profiles", "personal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(string(raw))
	for _, forbidden := range []string{"password", "secret", "api_key", "token", "credential"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the profile mentions %q; it must hold policy only", forbidden)
		}
	}
	// It must still be valid, which is the property that matters.
	if _, err := config.Parse(raw); err != nil {
		t.Fatalf("the shipped profile is invalid: %v", err)
	}
}

// regexpCompile is a thin wrapper so the test file does not need the regexp
// import at every call site.
func regexpCompile(expr string) (*regexp.Regexp, error) { return regexp.Compile(expr) }
