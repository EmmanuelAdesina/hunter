package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	envPath := filepath.Join("..", "..", "deploy", "systemd", "hunter.env.example")
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := string(raw)

	smtp, err := os.ReadFile(filepath.Join("..", "..", "internal", "notify", "smtp.go"))
	if err != nil {
		t.Fatal(err)
	}

	// Every environment variable named in the notifier must appear in the
	// template, so that installing from the template can actually deliver.
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
		if !strings.Contains(tmpl, name) {
			t.Errorf("the binary reads %s but the credential template omits it", name)
		}
	}

	// And the workflow must use the same names, so the two deployment paths do
	// not drift.
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "monitor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"EMAIL_SMTP_HOST", "EMAIL_SMTP_PORT", "EMAIL_USERNAME",
		"EMAIL_PASSWORD", "ALERT_RECIPIENT",
	} {
		if !strings.Contains(string(wf), name) {
			t.Errorf("the workflow omits %s, which the template documents", name)
		}
		if !strings.Contains(tmpl, name) {
			t.Errorf("the template omits %s, which the workflow documents", name)
		}
	}
}

// TestDeployScriptHasNoHardcodedCredentials verifies the installer carries no
// values. It creates the credential file empty on purpose.
func TestDeployScriptHasNoHardcodedCredentials(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install.sh"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(raw)

	for _, assignment := range []string{
		"EMAIL_PASSWORD=", "EMAIL_USERNAME=", "ALERT_RECIPIENT=",
	} {
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, assignment) {
				continue
			}
			_, value, _ := strings.Cut(line, "=")
			// Allow the template path, which is the only legitimate mention.
			if strings.Contains(value, "env.example") {
				continue
			}
			if strings.TrimSpace(strings.Trim(value, `"'`)) != "" {
				t.Errorf("install.sh assigns a value to %s; it must only copy the template",
					strings.TrimSuffix(assignment, "="))
			}
		}
	}

	// The credential file must be created with restrictive permissions and left
	// to the operator to fill in.
	if !strings.Contains(body, "0600") && !strings.Contains(body, "0640") {
		t.Error("install.sh never sets a restrictive mode on the credential file")
	}
	if !strings.Contains(body, "hunter.env.example") {
		t.Error("install.sh does not copy the empty template")
	}
}

// TestSystemdUnitsAreLockedDown asserts the hardening directives are present.
//
// These are the properties that keep a compromised workflow from becoming a
// compromised host. Dropping one silently widens the blast radius, so each is
// pinned rather than assumed.
func TestSystemdUnitsAreLockedDown(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "hunter.service"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(unit)

	required := []string{
		"NoNewPrivileges=true",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"PrivateDevices=true",
		"MemoryDenyWriteExecute=true",
		"RestrictSUIDSGID=true",
		"LockPersonality=true",
		"SystemCallArchitectures=native",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"ReadWritePaths=/var/lib/hunter",
		"UMask=0077",
	}
	for _, directive := range required {
		if !strings.Contains(body, directive) {
			t.Errorf("the unit is missing hardening directive: %s", directive)
		}
	}

	// The unit must run as a named unprivileged account, never as root.
	if !strings.Contains(body, "User=hunter") {
		t.Error("the unit does not drop to the service account")
	}
	if strings.Contains(body, "User=root") {
		t.Error("the unit runs as root")
	}

	// Credentials must come from a file, never from the unit or the command line.
	if !strings.Contains(body, "EnvironmentFile=") {
		t.Error("the unit does not read credentials from a file")
	}
	if strings.Contains(body, "Environment=EMAIL_") {
		t.Error("the unit sets a credential inline")
	}
	if strings.Contains(body, "--password") || strings.Contains(body, "PASSWORD=") {
		t.Error("a credential appears in the unit or its arguments")
	}

	// Nothing may listen.
	for _, forbidden := range []string{"ListenStream", "net.Listen", "ListenAndServe"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the unit declares a listener: %s", forbidden)
		}
	}
}

// TestTimerCatchesUpAfterDowntime verifies Persistent is set.
//
// A five-minute monitor that silently stops while the host is rebooted is worse
// than no monitor, because it looks healthy.
func TestTimerCatchesUpAfterDowntime(t *testing.T) {
	timer, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "hunter.timer"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(timer)

	if !strings.Contains(body, "Persistent=true") {
		t.Error("the timer does not catch up after downtime")
	}
	if !strings.Contains(body, "OnCalendar=") {
		t.Error("the timer has no schedule")
	}
	if !strings.Contains(body, "Unit=hunter.service") {
		t.Error("the timer does not name the unit it drives")
	}
	if !strings.Contains(body, "WantedBy=timers.target") {
		t.Error("the timer is not enabled into timers.target")
	}
}
