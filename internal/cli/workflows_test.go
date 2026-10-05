package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
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
	} `yaml:"jobs"`
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

// listWorkflows returns the workflow file names present.
func listWorkflows(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", ".github", "workflows"))
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestExactlyOneWorkflowRemains pins the consolidation.
//
// The scan runs on a host as a systemd timer. A GitHub workflow that also
// scanned would use a different state store and every alert would arrive twice.
func TestExactlyOneWorkflowRemains(t *testing.T) {
	names := listWorkflows(t)
	if len(names) != 1 || names[0] != "test.yml" {
		t.Errorf("workflows = %v, want only test.yml; the scan is scheduled by the host timer", names)
	}
}

// TestNoWorkflowSchedulesAScan verifies nothing reintroduces a second
// scheduler.
func TestNoWorkflowSchedulesAScan(t *testing.T) {
	for _, name := range listWorkflows(t) {
		raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "schedule:") {
			t.Errorf("%s declares a schedule; only the host timer may schedule a scan", name)
		}
		if strings.Contains(string(raw), "cron:") {
			t.Errorf("%s declares a cron entry; only the host timer may schedule a scan", name)
		}
	}
}

// TestNoWorkflowReadsDeliveryCredentials verifies the mail credential is not
// requested anywhere in version control.
//
// The repository is public. The credential lives only on the host that sends
// the mail, so no workflow may hold it, and none may ask for it.
func TestNoWorkflowReadsDeliveryCredentials(t *testing.T) {
	for _, name := range listWorkflows(t) {
		raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"secrets.EMAIL_PASSWORD", "secrets.EMAIL_USERNAME",
			"secrets.EMAIL_SMTP", "secrets.ALERT_RECIPIENT",
		} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s references %s; delivery is the host's job", name, forbidden)
			}
		}
	}
}

// TestWorkflowsAreValidYAML verifies every workflow parses. A workflow that does
// not parse is silently skipped, so a broken file looks like a passing suite.
func TestWorkflowsAreValidYAML(t *testing.T) {
	for _, name := range listWorkflows(t) {
		t.Run(name, func(t *testing.T) {
			wf := loadWorkflow(t, name)
			if len(wf.Jobs) == 0 {
				t.Error("workflow declares no jobs")
			}
		})
	}
}

// TestWorkflowShellIsValidBash verifies every run block is syntactically valid.
//
// Shell inside a workflow is compiled nowhere, so a typo sits unnoticed until
// CI runs. The check is skipped when bash is unavailable rather than failing,
// so the suite still runs on a host without a POSIX shell.
func TestWorkflowShellIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available; skipping workflow shell validation")
	}

	dir := t.TempDir()
	total := 0
	for _, name := range listWorkflows(t) {
		wf := loadWorkflow(t, name)
		for jobName, job := range wf.Jobs {
			for i, step := range job.Steps {
				if step.Run == "" {
					continue
				}
				total++
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
	if total == 0 {
		t.Error("no shell steps were inspected; the check is not running")
	}
}

// TestEnvExampleHoldsNoValues verifies the credential template ships empty.
//
// The template is copied to the live credential file during installation, so a
// real value left in it would be published with the repository the moment the
// repository was made public. Every key must be present and every value blank.
func TestEnvExampleHoldsNoValues(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "systemd", "hunter.env.example")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	required := []string{
		"EMAIL_SMTP_HOST", "EMAIL_SMTP_PORT", "EMAIL_USERNAME",
		"EMAIL_PASSWORD", "ALERT_RECIPIENT", "EMAIL_FROM_NAME",
	}

	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			t.Errorf("line %d is neither a comment nor an assignment: %q", i+1, trimmed)
			continue
		}
		key = strings.TrimSpace(key)
		seen[key] = true
		if strings.TrimSpace(value) != "" {
			t.Errorf("line %d sets a value for %s; the template must ship empty", i+1, key)
		}
		if strings.Contains(trimmed, `"`) || strings.Contains(trimmed, "'") {
			t.Errorf("line %d is quoted; the template shows the bare form", i+1)
		}
	}

	for _, key := range required {
		if !seen[key] {
			t.Errorf("the template is missing %s", key)
		}
	}
}

// TestEnvExampleKeysMatchTheBinary verifies the template documents exactly the
// variables the code reads.
//
// A key in the template that nothing reads is a credential on disk for no
// reason. A key the code reads that the template omits is a scan that silently
// generates alerts and delivers nothing.
func TestEnvExampleKeysMatchTheBinary(t *testing.T) {
	tmpl, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "hunter.env.example"))
	if err != nil {
		t.Fatal(err)
	}

	smtp, err := os.ReadFile(filepath.Join("..", "..", "internal", "notify", "smtp.go"))
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(string(smtp), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Env") || !strings.Contains(line, "=") {
			continue
		}
		_, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		name := strings.Trim(strings.TrimSpace(value), `"`)
		if !strings.HasPrefix(name, "EMAIL_") && !strings.HasPrefix(name, "ALERT_") {
			continue
		}
		if !strings.Contains(string(tmpl), name) {
			t.Errorf("the binary reads %s but the credential template omits it", name)
		}
	}
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
	if _, err := config.Parse(raw); err != nil {
		t.Fatalf("the shipped profile is invalid: %v", err)
	}
}

// TestShippedProfileAlertsOnFreshOpportunities pins the profile to the intended
// posture: new launches, plus changes to existing programs that are themselves
// recent, with the access gates as a hard filter.
func TestShippedProfileAlertsOnFreshOpportunities(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "profiles", "personal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("the shipped profile is invalid: %v", err)
	}

	if !p.Notifications.AlertOnNewPrograms {
		t.Error("new-program alerts are off; the channel would never fire")
	}
	if p.NewProgramWindow() <= 0 {
		t.Error("no launch window is set")
	}
	if !p.Notifications.RequireEligible {
		t.Error("alerts are not gated on eligibility; a program failing an access " +
			"requirement could be announced")
	}
	// The gates themselves must remain strict.
	if p.Access.KYCRequired != domain.TriNo {
		t.Error("KYC is now acceptable; that reverses the stated constraint")
	}
	if p.Access.MaxReputationPoints <= 0 {
		t.Error("no reputation ceiling is set")
	}
	if p.Access.MaxSubmissionFeeUSD < 0 {
		t.Error("no submission fee ceiling is set")
	}
	if p.Access.AcceptUnknownAccessGates {
		t.Error("unknown access gates are accepted; a program whose requirements " +
			"could not be read could be announced")
	}

	// Triggers for already-running programs must be on, and must be gated on the
	// recency of the CHANGE rather than on the age of the program. A five-year-old
	// program that added an API nine minutes ago is the most valuable event this
	// system can report.
	if !p.Notifications.AlertOnMaterialChange {
		t.Error("material-change alerts are off; a fresh change to an existing program would be missed")
	}
	if !p.Notifications.AlertOnScopeExpansion {
		t.Error("scope-expansion alerts are off; a new API on an existing program would be missed")
	}
	if w := p.ChangeWindowFor(domain.ChangeAPIAdded); w <= 0 {
		t.Error("no change window governs API additions; a change trigger would be un-gated")
	}
	if w := p.ChangeWindowFor(domain.ChangeReputationLowered); w <= 0 {
		t.Error("no change window governs a lowered reputation requirement")
	}
	if w := p.ChangeWindowFor(domain.ChangeProgramReactivated); w <= 0 {
		t.Error("no change window governs a reactivation")
	}
}

// TestRepositoryContainsNoCredentials verifies no committed file holds a value
// that looks like a live credential.
//
// The repository is public, so a credential committed at any point is disclosed
// immediately and must be treated as compromised.
func TestRepositoryContainsNoCredentials(t *testing.T) {
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

	skipDirs := map[string]bool{".git": true, "bin": true, "dist": true, "fixtures": true, "state": true}
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
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".yml", ".yaml", ".sh", ".md", ".json", ".mod", ".sum", "":
		default:
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		checked++
		for _, p := range patterns {
			re, cerr := regexp.Compile(p.re)
			if cerr != nil {
				continue
			}
			if loc := re.FindIndex(body); loc != nil {
				// The shape is reported, never the value, so the finding itself
				// cannot leak a secret into a build log.
				t.Errorf("%s: matches %s near byte %d; if this is a real credential, "+
					"revoke it before anything else",
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
