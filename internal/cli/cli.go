// Package cli implements the command-line interface.
//
// Commands are thin: they parse flags, wire dependencies, call the pipeline or
// query state, and render. No business rule lives here. That keeps the same
// behaviour available to a future API or dashboard without duplicating logic.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/notify"
	"github.com/eadeshina/hunter/internal/obs"
	"github.com/eadeshina/hunter/internal/source"
	"github.com/eadeshina/hunter/internal/source/hackenproof"
	"github.com/eadeshina/hunter/internal/state"
)

// Env bundles the process environment so that commands are testable without
// mutating global state.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Args   []string
	// Now supplies the current time.
	Now func() time.Time
	// LookupEnv reads environment variables, standing in for os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// DefaultEnv returns the real process environment.
func DefaultEnv() *Env {
	return &Env{
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Args:      os.Args[1:],
		Now:       time.Now,
		LookupEnv: os.LookupEnv,
	}
}

// Run dispatches a command and returns a process exit code.
//
// Exit codes are meaningful so that a scheduled workflow can distinguish a
// clean run with no alerts from a run that actually broke:
//
//	0  success
//	1  the command failed
//	2  configuration is invalid
//	3  the scan ran but its results are untrustworthy
const (
	exitOK          = 0
	exitFailure     = 1
	exitBadConfig   = 2
	exitDegradedRun = 3
)

// Run executes the CLI.
func Run(ctx context.Context, env *Env) int {
	if len(env.Args) == 0 {
		usage(env.Stderr)
		return exitFailure
	}

	cmd := env.Args[0]
	rest := env.Args[1:]

	switch cmd {
	case "scan", "sync":
		return cmdScan(ctx, env, rest)
	case "programs":
		return cmdPrograms(env, rest)
	case "explain":
		return cmdExplain(env, rest)
	case "history":
		return cmdHistory(env, rest)
	case "replay":
		return cmdReplay(env, rest)
	case "alerts":
		return cmdAlerts(env, rest)
	case "windows":
		return cmdWindows(env, rest)
	case "validate-config":
		return cmdValidateConfig(env, rest)
	case "test-fixtures":
		return cmdTestFixtures(env, rest)
	case "test-email":
		return cmdTestEmail(env, rest)
	case "version":
		fmt.Fprintln(env.Stdout, version)
		return exitOK
	case "help", "-h", "--help":
		usage(env.Stdout)
		return exitOK
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n\n", cmd)
		usage(env.Stderr)
		return exitFailure
	}
}

// commonFlags are the flags every command shares.
type commonFlags struct {
	profilePath string
	stateDir    string
	logLevel    string
	asJSON      bool
}

// register wires the common flags.
func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.profilePath, "profile", defaultProfilePath, "path to the researcher profile")
	fs.StringVar(&c.stateDir, "state", defaultStateDir, "directory holding persisted state")
	fs.StringVar(&c.logLevel, "log-level", "info", "log verbosity: debug|info|warn|error")
	fs.BoolVar(&c.asJSON, "json", false, "emit machine-readable JSON")
}

// defaults match the repository layout so that the common case needs no flags.
const (
	defaultProfilePath = "configs/profiles/personal.yaml"
	defaultStateDir    = "state"
)

// parseFlags parses a flag set, reporting errors through the returned code.
func parseFlags(fs *flag.FlagSet, env *Env, args []string) bool {
	fs.SetOutput(env.Stderr)
	if err := fs.Parse(args); err != nil {
		return false
	}
	return true
}

// buildEnv assembles the runtime from flags: logger, state store, profile.
func (c *commonFlags) buildEnv(env *Env) (*config.Profile, state.StateStore, *obs.Logger, error) {
	level, ok := obs.ParseLevel(c.logLevel)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid --log-level %q: want debug|info|warn|error", c.logLevel)
	}
	logger := obs.New(level)

	profile, err := config.Load(c.profilePath)
	if err != nil {
		return nil, nil, logger, err
	}
	store := state.NewFileStore(c.stateDir)
	return profile, store, logger, nil
}

// errConfig marks configuration failures so the exit code can be distinguished.
type errConfig struct{ err error }

func (e *errConfig) Error() string { return e.err.Error() }
func (e *errConfig) Unwrap() error { return e.err }

// newSources builds the adapters the profile enables.
//
// Adapters are registered in one place. Adding a platform means adding a
// registration line, not editing the pipeline.
func newSources(profile *config.Profile) ([]domain.ProgramSource, error) {
	reg := source.NewRegistry()
	reg.Register(hackenproof.AdapterName, func() (domain.ProgramSource, error) {
		cfg := profile.SourceConfigFor(hackenproof.AdapterName)
		// The adapter's declared pacing is the floor, not the profile's value.
		// A profile that spaces requests more tightly than the adapter says the
		// host tolerates would otherwise turn a politeness setting into a
		// rate-limit generator, and the resulting 429 costs coverage silently.
		caps := (&hackenproof.Source{}).Capabilities()

		interval := profile.ScanDuration("min_request_interval")
		if caps.MinRequestInterval > interval {
			interval = caps.MinRequestInterval
		}
		concurrent := profile.Scan.MaxConcurrent
		if caps.MaxConcurrent > 0 && caps.MaxConcurrent < concurrent {
			concurrent = caps.MaxConcurrent
		}

		client := source.NewClient(source.ClientConfig{
			Timeout:        profile.ScanDuration("request_timeout"),
			MaxRetries:     profile.Scan.MaxRetries,
			RetryBaseDelay: profile.ScanDuration("retry_base_delay"),
			MaxRetryDelay:  profile.ScanDuration("max_retry_delay"),
			MinInterval:    interval,
			UserAgent:      profile.Scan.UserAgent,
			MaxConcurrent:  concurrent,
		}, nil)
		return hackenproof.New(hackenproof.Options{
			Client:             client,
			BaseURL:            cfg.BaseURL,
			ListPath:           cfg.ListPath,
			DetailPathTemplate: cfg.DetailPathTemplate,
			PerPage:            profile.Scan.PerPage,
			MaxPages:           profile.Scan.MaxPages,
			PageConcurrency:    profile.Scan.ListingConcurrency,
		})
	})

	names := profile.EnabledSources()
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: the profile enables no sources", source.ErrConfig)
	}
	return reg.Build(names)
}

// nonEmpty filters blank strings.
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func usage(w io.Writer) {
	fmt.Fprint(w, `hunter - personal bug-bounty opportunity monitor

Usage:
  hunter <command> [flags]

Commands:
  scan                Discover, evaluate, and alert in one pass.
    --full              Traverse the entire listing rather than a page budget.
    --dry-run           Generate and record alerts without sending them.
    --no-details        Discover only; skip detail fetches.
  sync                Alias for scan, conventionally run manually.
  programs            List known programs from state.
    --eligible          Only programs the profile accepts.
    --new               Only programs discovered in the last scan.
    --changed           Only programs that changed in the last scan.
    --source <name>     Filter by source.
    --limit <n>         Maximum rows.
  explain <id>        Show the full eligibility decision and reasoning.
  history <id>        Show recorded changes for one program.
  replay <id>         Replay saved history and windows as a read-only timeline.
    --limit <n>         Maximum events (default 200; zero is unlimited).
  alerts              List recorded alerts.
    --undelivered       Only alerts that have not been confirmed delivered.
    --limit <n>         Maximum rows.
  windows             List recorded opportunity windows and their current status.
    --open              Only windows that remain open.
    --program <id>      Filter by program ID, slug, or unambiguous name.
    --limit <n>         Maximum rows.
  validate-config     Parse and validate the profile.
  test-fixtures       Re-parse checked-in fixtures and report what was found.
  test-email [id]     Send one rendered sample so the email layout can be checked.
  version             Print the build version.

Common flags:
  --profile <path>    Profile to load (default `+defaultProfilePath+`).
  --state <dir>       State directory (default `+defaultStateDir+`).
  --log-level <lvl>   debug|info|warn|error.
  --json              Machine-readable output.

Notification is configured through the environment only:
  `+notify.EnvSMTPHost+`, `+notify.EnvSMTPPort+`,
  `+notify.EnvUsername+`, `+notify.EnvPassword+`, `+notify.EnvRecipient+`
`)
}

// version is stamped at link time by the release workflow.
var version = "dev"

// Version returns the build version, so a caller can report it before running.
func Version() string { return version }

// SetVersion records the build version.
//
// It exists so that the linker-stamped value in package main can reach the CLI
// without the CLI importing main, and so that the value is set once at startup
// rather than read from a mutable global throughout.
func SetVersion(v string) {
	if v != "" {
		version = v
	}
}
