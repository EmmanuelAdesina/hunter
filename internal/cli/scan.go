package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/eadeshina/hunter/internal/alerts"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/notify"
	"github.com/eadeshina/hunter/internal/obs"
	"github.com/eadeshina/hunter/internal/pipeline"
)

// notifierFactory defers notifier construction so that the environment is read
// when the command runs rather than at process start.
type notifierFactory func() notify.Notifier

// notifierFromEnv builds an SMTP notifier from the environment.
//
// A missing configuration yields nil rather than an error: generating and
// recording alerts without transmitting them is a legitimate mode, used for dry
// runs and for validating a profile before wiring credentials.
func notifierFromEnv(env *Env) notify.Notifier {
	cfg, err := loadSMTPConfig(env)
	if err != nil {
		return nil
	}
	return notify.NewSMTPNotifier(cfg, 0)
}

// loadSMTPConfig reads delivery settings through the injected environment.
func loadSMTPConfig(env *Env) (notify.SMTPConfig, error) {
	get := func(key string) string {
		if env.LookupEnv == nil {
			return ""
		}
		v, _ := env.LookupEnv(key)
		return v
	}

	cfg := notify.SMTPConfig{
		Host:      strings.TrimSpace(get(notify.EnvSMTPHost)),
		Username:  strings.TrimSpace(get(notify.EnvUsername)),
		Password:  get(notify.EnvPassword),
		Recipient: strings.TrimSpace(get(notify.EnvRecipient)),
		FromName:  strings.TrimSpace(get(notify.EnvFromName)),
		Port:      587,
	}
	if p := strings.TrimSpace(get(notify.EnvSMTPPort)); p != "" {
		port, err := parsePort(p)
		if err != nil {
			return cfg, err
		}
		cfg.Port = port
	}
	if !cfg.Configured() {
		return cfg, fmt.Errorf("%w: delivery environment is incomplete", notify.ErrNotConfigured)
	}
	return cfg, nil
}

func parsePort(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("%s: %q is not a valid port", notify.EnvSMTPPort, s)
	}
	return n, nil
}

// cmdScan runs a complete scan.
func cmdScan(ctx context.Context, env *Env, args []string) int {
	var (
		common    commonFlags
		full      bool
		dryRun    bool
		noDetails bool
	)
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	common.register(fs)
	fs.BoolVar(&full, "full", false, "traverse the entire listing")
	fs.BoolVar(&dryRun, "dry-run", false, "generate and record alerts without sending")
	fs.BoolVar(&noDetails, "no-details", false, "skip detail fetches")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	profile, store, logger, err := common.buildEnv(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "scan: %v\n", err)
		return classifyConfigError(err)
	}

	sources, err := newSources(profile)
	if err != nil {
		fmt.Fprintf(env.Stderr, "scan: %v\n", err)
		return exitBadConfig
	}

	if full {
		logger.Debug("full traversal requested; the profile default is already unbounded")
	}

	cfg := pipeline.Config{
		Profile:      profile,
		Sources:      sources,
		Store:        store,
		Logger:       logger,
		Now:          env.Now,
		FetchDetails: profile.Scan.FetchDetails && !noDetails,
		DryRun:       dryRun || !profile.Notifications.Enabled,
		Concurrency:  profile.Scan.MaxConcurrent,
	}
	if n := newNotifier(env)(); n != nil {
		cfg.Notifier = n
	} else {
		logger.Info("delivery is not configured; alerts will be generated and recorded but not sent",
			"hint", "set "+notify.EnvSMTPHost+", "+notify.EnvSMTPPort+", "+notify.EnvUsername+
				", "+notify.EnvPassword+" and "+notify.EnvRecipient+" to enable email")
	}

	scanner, err := pipeline.New(cfg)
	if err != nil {
		fmt.Fprintf(env.Stderr, "scan: %v\n", err)
		return exitFailure
	}

	res, runErr := scanner.Scan(ctx)

	if common.asJSON {
		if err := writeJSON(env.Stdout, buildScanReport(res)); err != nil {
			fmt.Fprintf(env.Stderr, "scan: writing json: %v\n", err)
			return exitFailure
		}
	} else {
		renderScan(env.Stdout, res)
	}

	degraded, why := res.Metrics.Degraded()
	if degraded {
		fmt.Fprintf(env.Stderr, "\nscan results are untrustworthy: %s\n", why)
		return exitDegradedRun
	}

	// A profile that enables notifications but has no delivery channel is the
	// quietest possible failure mode: every scan succeeds, alerts accumulate,
	// and none is ever received. It is reported on stderr so it is visible in a
	// terminal and in the journal. The exit code is unchanged, because the scan
	// itself did its job and the cause is a configuration fault, not a fault in
	// the scan.
	if !cfg.DryRun && profile.Notifications.Enabled && cfg.Notifier == nil && len(res.Alerts) > 0 {
		fmt.Fprintf(env.Stderr,
			"\nWARNING: %d alert(s) were generated but NOT delivered.\n"+
				"         The profile enables notifications, so a delivery channel was\n"+
				"         expected. Check the delivery environment variables, starting\n"+
				"         with %s.\n",
			len(res.Alerts), notify.EnvSMTPHost)
	}

	if runErr != nil {
		return exitFailure
	}
	return exitOK
}

// isConfigError reports whether an error is a configuration problem, so that the
// exit code can distinguish "fix your profile" from "something broke".
func isConfigError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid profile") ||
		strings.Contains(msg, "read profile") ||
		strings.Contains(msg, "parse profile")
}

// classifyConfigError maps a load failure to an exit code.
func classifyConfigError(err error) int {
	if isConfigError(err) {
		return exitBadConfig
	}
	return exitFailure
}

// scanReport is the machine-readable form of a scan result.
type scanReport struct {
	Metrics  scanMetrics      `json:"metrics"`
	Alerts   []alertSummary   `json:"alerts"`
	Programs []programSummary `json:"programs,omitempty"`
	Errors   []string         `json:"errors,omitempty"`
	Degraded string           `json:"degraded,omitempty"`
}

// scanMetrics is the JSON view of the counters.
type scanMetrics struct {
	ScanID           string        `json:"scan_id"`
	Source           string        `json:"source"`
	Discovered       int           `json:"discovered"`
	Fetched          int           `json:"fetched"`
	FetchFailed      int           `json:"fetch_failed"`
	New              int           `json:"new"`
	Changed          int           `json:"changed"`
	Eligible         int           `json:"eligible"`
	Rejected         int           `json:"rejected"`
	Quarantined      int           `json:"quarantined"`
	AlertsGenerated  int           `json:"alerts_generated"`
	AlertsSuppressed int           `json:"alerts_suppressed"`
	AlertsSent       int           `json:"alerts_sent"`
	AlertsFailed     int           `json:"alerts_failed"`
	AlertsSkipped    int           `json:"alerts_skipped"`
	Errors           int           `json:"errors"`
	Coverage         *CoverageJSON `json:"coverage,omitempty"`
	DurationMS       int64         `json:"duration_ms"`
}

func metricsView(res pipeline.Result) scanMetrics {
	m := res.Metrics
	return scanMetrics{
		ScanID: m.ScanID, Source: m.Source,
		Discovered: m.Discovered, Fetched: m.Fetched, FetchFailed: m.FetchFailed,
		New: m.New, Changed: m.Changed, Eligible: m.Eligible, Rejected: m.Rejected,
		Quarantined: m.Quarantined, AlertsGenerated: m.AlertsGenerated,
		AlertsSuppressed: m.AlertsSuppressed, AlertsSent: m.AlertsSent,
		AlertsFailed: m.AlertsFailed, AlertsSkipped: m.AlertsSkipped,
		Errors: m.Errors, DurationMS: m.Duration.Milliseconds(),
		Coverage: &CoverageJSON{
			Expected:        m.Expected,
			Observed:        m.Observed,
			Missing:         m.Missing,
			Absent:          m.Absent,
			Departed:        m.Departed,
			Ratio:           m.CoverageRatio,
			MinRatio:        m.MinCoverageRatio,
			MissingPrograms: res.Coverage.MissingReport(),
		},
	}
}

func buildScanReport(res pipeline.Result) scanReport {
	rep := scanReport{
		Metrics:  metricsView(res),
		Alerts:   buildAlertSummaries(res.Alerts),
		Programs: buildProgramSummaries(res.Programs),
	}
	for _, err := range res.Errors {
		rep.Errors = append(rep.Errors, err.Error())
	}
	if degraded, why := res.Metrics.Degraded(); degraded {
		rep.Degraded = why
	}
	return rep
}

// renderScan writes the human-readable scan summary.
func renderScan(w io.Writer, res pipeline.Result) {
	m := res.Metrics
	fmt.Fprintln(w)
	fmt.Fprintln(w, m.Summary())
	fmt.Fprintln(w)

	if degraded, why := m.Degraded(); degraded {
		fmt.Fprintf(w, "WARNING: %s\n", why)
		fmt.Fprintln(w, "         Silence from a degraded scan does not mean absence of opportunities.")
		fmt.Fprintln(w)
	}

	// Coverage is printed on every run, not only when it is bad. A number that
	// appears only once it has already failed is a number nobody learns to read,
	// and it turns a gradual regression into an apparently sudden one.
	for _, line := range obs.CoverageReport(m, res.Coverage.MissingReport()) {
		fmt.Fprintln(w, line)
	}
	if len(res.Coverage.MissingReport()) > 0 {
		fmt.Fprintln(w)
	}

	alerts.SortByPriority(res.Alerts)
	if len(res.Alerts) > 0 {
		fmt.Fprintf(w, "Alerts (%d):\n", len(res.Alerts))
		for _, a := range res.Alerts {
			fmt.Fprintf(w, "  %s\n", a.Subject)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "No alerts.")
		fmt.Fprintln(w)
	}

	rows := make([]pipeline.Evaluated, 0, len(res.Programs))
	for _, e := range res.Programs {
		if e.Decision.Eligible {
			rows = append(rows, e)
		}
	}
	if len(rows) > 0 {
		fmt.Fprintln(w, "Eligible programs by attention priority:")
		fmt.Fprintf(w, "  %-46s %5s %7s  %s\n", "PROGRAM", "SCORE", "AGE", "TOP REASON")
		if len(rows) > 10 {
			rows = rows[:10]
		}
		for _, e := range rows {
			age := ""
			if e.Fresh.FirstSeenAge > 0 {
				age = domain.HumanizeDuration(e.Fresh.FirstSeenAge)
			}
			fmt.Fprintf(w, "  %-46s %5d %7s  %s\n",
				truncate(e.Program.Name, 46), e.Triage.Total, age, firstReason(e.Decision))
		}
		fmt.Fprintln(w)
	}

	for _, err := range res.Errors {
		fmt.Fprintf(w, "error: %v\n", err)
	}
}

// firstReason renders the most informative single line from a decision.
//
// Checks about record integrity are skipped in favour of a substantive fact.
// "fully understood" is true of nearly every well-formed record and tells the
// reader nothing about why the program is worth their time; "50 reputation
// points <= configured maximum of 80" does.
func firstReason(d domain.EligibilityDecision) string {
	if d.Eligible {
		for _, r := range d.Reasons {
			if !isIntegrityReason(r) {
				return r
			}
		}
		if len(d.Reasons) > 0 {
			return d.Reasons[0]
		}
		return "eligible"
	}
	if len(d.Blockers) > 0 {
		return d.Blockers[0].Reason()
	}
	return "not eligible"
}

// integrityPhrases identify checks that describe record quality rather than
// opportunity.
var integrityPhrases = []string{
	"fully understood",
	"partially understood",
	"access facts present",
}

// isIntegrityReason reports whether a reason line describes record quality.
func isIntegrityReason(r string) bool {
	for _, p := range integrityPhrases {
		if strings.Contains(r, p) {
			return true
		}
	}
	return false
}

// truncate shortens a string for column alignment.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// alertSummary is the JSON view of a generated alert.
type alertSummary struct {
	Fingerprint string   `json:"fingerprint"`
	Kind        string   `json:"kind"`
	ProgramID   string   `json:"program_id"`
	Program     string   `json:"program"`
	Subject     string   `json:"subject"`
	Priority    int      `json:"priority"`
	Eligible    bool     `json:"eligible"`
	Changes     []string `json:"changes,omitempty"`
}

// programSummary is the JSON view of an evaluated program.
type programSummary struct {
	ProgramID string   `json:"program_id"`
	Name      string   `json:"name"`
	Eligible  bool     `json:"eligible"`
	Priority  int      `json:"priority"`
	Crypto    string   `json:"crypto_kind,omitempty"`
	Surfaces  []string `json:"surfaces,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
	New       bool     `json:"new"`
	Changed   bool     `json:"changed"`
}

// buildAlertSummaries converts generated alerts for output.
func buildAlertSummaries(in []domain.Alert) []alertSummary {
	out := make([]alertSummary, 0, len(in))
	for _, a := range in {
		out = append(out, alertSummary{
			Fingerprint: a.ShortFingerprint(),
			Kind:        string(a.Kind),
			ProgramID:   a.ProgramID,
			Program:     a.Program.Name,
			Subject:     a.Subject,
			Priority:    a.Triage.Total,
			Eligible:    a.Decision.Eligible,
			Changes:     a.Changes.Kinds(),
		})
	}
	return out
}

// buildProgramSummaries converts evaluated programs for output.
func buildProgramSummaries(in []pipeline.Evaluated) []programSummary {
	out := make([]programSummary, 0, len(in))
	for _, e := range in {
		out = append(out, programSummary{
			ProgramID: e.Program.ID,
			Name:      e.Program.Name,
			Eligible:  e.Decision.Eligible,
			Priority:  e.Triage.Total,
			Crypto:    string(e.Program.CryptoKind),
			Surfaces:  e.Program.SurfaceTags,
			Reasons:   e.Decision.Reasons,
			New:       e.Diff.IsNew,
			Changed:   !e.Diff.IsNew && !e.Diff.Changes.Empty(),
		})
	}
	return out
}

// ensure the errors package stays referenced for callers relying on helpers.
var _ = errors.Is

// newNotifier returns a factory that builds the delivery channel.
//
// Construction is deferred so that an absent configuration is discovered at scan
// time, where it can be reported as "recorded but not sent" rather than failing
// the command outright.
func newNotifier(env *Env) notifierFactory {
	return func() notify.Notifier { return notifierFromEnv(env) }
}

// CoverageJSON is the machine-readable coverage accounting for one scan.
//
// It is a first-class part of the report rather than a log line because the
// question "did this sweep actually see the platform" has to be answerable by a
// scheduler or a dashboard without parsing prose.
type CoverageJSON struct {
	Expected int `json:"expected"`
	Observed int `json:"observed"`
	Missing  int `json:"missing"`
	Absent   int `json:"absent"`

	// Departed counts programs removed from state because the platform finished
	// with them. It is a legitimate outcome and is never counted as a failure.
	Departed int `json:"departed"`

	// Ratio is observed over expected, or -1 when there was nothing to expect.
	Ratio float64 `json:"ratio"`

	// MinRatio is the floor this scan was judged against, carried so that a
	// degraded report states the standard it failed rather than making the reader
	// reconstruct it from configuration.
	MinRatio float64 `json:"min_ratio"`

	// MissingPrograms names the programs behind Missing.
	MissingPrograms []string `json:"missing_programs,omitempty"`
}
