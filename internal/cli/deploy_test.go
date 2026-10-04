package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// TestScanYieldsToProduction asserts the unit cannot compete with production
// workloads for the processor.
//
// The scan shares a single core with the production services on the target
// host, so scheduling it at normal priority would let a scan contribute to
// latency on a service people are actually using.
func TestScanYieldsToProduction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "hunter.service"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	if !strings.Contains(body, "Nice=19") {
		t.Error("the unit does not request the lowest normal CPU priority")
	}
	if !strings.Contains(body, "IOSchedulingClass=idle") {
		t.Error("the unit does not use the idle I/O class")
	}
}
