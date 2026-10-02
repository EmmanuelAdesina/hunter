// Package obs provides structured logging and scan metrics.
//
// The goal is useful output in a CI log, not an observability platform. Every
// scan emits one summary line with the counts an operator needs to tell a normal
// run from a degraded one, plus per-phase detail for anything unusual.
package obs

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Level selects log verbosity.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// ParseLevel validates a configured level.
func ParseLevel(s string) (Level, bool) {
	switch Level(s) {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
		return Level(s), true
	default:
		return LevelInfo, false
	}
}

func (l Level) slog() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Logger is a thin wrapper that keeps call sites terse and consistent.
type Logger struct {
	*slog.Logger
}

// New builds a logger writing to stderr.
//
// Output goes to stderr so that stdout stays clean for machine-readable command
// output, which several commands emit.
func New(level Level) *Logger {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level.slog(),
		// Keeping full timestamps makes durations in logs interpretable
		// across workflow runs.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String("ts", a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z"))
			}
			return a
		},
	})
	return &Logger{Logger: slog.New(h)}
}

// Discard returns a logger that drops everything, for tests.
func Discard() *Logger {
	h := slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1})
	return &Logger{Logger: slog.New(h)}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// With returns a logger carrying additional attributes.
func (l *Logger) With(args ...any) *Logger { return &Logger{Logger: l.Logger.With(args...)} }

// Phase names used as the "phase" attribute.
const (
	PhaseDiscover = "discover"
	PhaseFetch    = "fetch"
	PhaseDiff     = "diff"
	PhasePolicy   = "policy"
	PhaseScore    = "score"
	PhaseAlert    = "alert"
	PhaseNotify   = "notify"
	PhasePersist  = "persist"
)

// ScanMetrics are the counters reported for one scan.
//
// Every field is a plain observation of what happened. Nothing is estimated or
// extrapolated, so a summary line can be trusted without cross-checking.
type ScanMetrics struct {
	ScanID   string        `json:"scan_id"`
	Source   string        `json:"source"`
	Started  time.Time     `json:"started_at"`
	Duration time.Duration `json:"duration"`

	Discovered  int `json:"discovered"`
	Fetched     int `json:"fetched"`
	FetchFailed int `json:"fetch_failed"`
	ListingOnly int `json:"listing_only"`

	// Evaluated counts every program that produced a decision, from either tier.
	// This is the number that says whether the run saw anything at all.
	Evaluated int `json:"evaluated"`

	// Attempted counts every evaluation the scan tried to perform.
	Attempted int `json:"attempted"`
	New       int `json:"new"`
	Changed   int `json:"changed"`

	// MinorChanged counts programs whose only differences were low severity,
	// such as a moving submission count. They are real observations but not
	// changes to scope or requirements, and they are reported separately so
	// "changed" means the same thing here as it does in the query and in the
	// change history.
	MinorChanged     int `json:"minor_changed"`
	Eligible         int `json:"eligible"`
	Rejected         int `json:"rejected"`
	Quarantined      int `json:"quarantined"`
	AlertsGenerated  int `json:"alerts_generated"`
	AlertsSuppressed int `json:"alerts_suppressed"`
	AlertsSent       int `json:"alerts_sent"`
	AlertsFailed     int `json:"alerts_failed"`
	AlertsSkipped    int `json:"alerts_skipped"`
	Errors           int `json:"errors"`
}

// Summary renders the one-line form used in CI logs.
//
// The format is fixed and greppable: key=value pairs, one line, no nesting.
func (m ScanMetrics) Summary() string {
	return "scan_id=" + m.ScanID +
		" source=" + m.Source +
		" discovered=" + itoa(m.Discovered) +
		" evaluated=" + itoa(m.Evaluated) +
		" fetched=" + itoa(m.Fetched) +
		" listing_only=" + itoa(m.ListingOnly) +
		" new=" + itoa(m.New) +
		" changed=" + itoa(m.Changed) +
		" minor_changed=" + itoa(m.MinorChanged) +
		" eligible=" + itoa(m.Eligible) +
		" rejected=" + itoa(m.Rejected) +
		" alerts=" + itoa(m.AlertsGenerated) +
		" sent=" + itoa(m.AlertsSent) +
		" failed=" + itoa(m.AlertsFailed) +
		" errors=" + itoa(m.Errors) +
		" duration=" + m.Duration.Round(10*time.Millisecond).String()
}

// Degraded reports whether the run shows signs of a problem worth a human look.
//
// A run that evaluated nothing, or that failed on every attempt, is a run whose
// silence says nothing about the platform. Treating that as "no news" would be
// the most dangerous possible failure for a monitoring system.
//
// Note what is deliberately *not* part of this: a run that performed no detail
// fetches is healthy. The cheap tier is designed to cover the whole platform on a
// steady scan, so zero detail reads is the expected steady state rather than a
// symptom.
func (m ScanMetrics) Degraded() (bool, string) {
	switch {
	case m.Discovered == 0:
		return true, "no programs were discovered"
	case m.Evaluated == 0:
		return true, "no programs could be evaluated"
	case m.Fetched == 0 && m.ListingOnly == 0:
		return true, "no programs were examined by either tier"
	case m.Attempted > 0 && m.Evaluated == 0:
		return true, "every evaluation attempt failed"
	default:
		return false, ""
	}
}

// attrs renders the metrics as log attributes.
func (m ScanMetrics) attrs() []any {
	return []any{
		"scan_id", m.ScanID,
		"source", m.Source,
		"discovered", m.Discovered,
		"fetched", m.Fetched,
		"fetch_failed", m.FetchFailed,
		"listing_only", m.ListingOnly,
		"evaluated", m.Evaluated,
		"attempted", m.Attempted,
		"new", m.New,
		"changed", m.Changed,
		"minor_changed", m.MinorChanged,
		"eligible", m.Eligible,
		"rejected", m.Rejected,
		"quarantined", m.Quarantined,
		"alerts_generated", m.AlertsGenerated,
		"alerts_suppressed", m.AlertsSuppressed,
		"alerts_sent", m.AlertsSent,
		"alerts_failed", m.AlertsFailed,
		"alerts_skipped", m.AlertsSkipped,
		"errors", m.Errors,
		"duration", m.Duration.Round(time.Millisecond).String(),
	}
}

// LogSummary emits the end-of-scan summary line.
func (l *Logger) LogSummary(m ScanMetrics) {
	l.Info("scan complete", m.attrs()...)
	if degraded, why := m.Degraded(); degraded {
		l.Warn("scan appears degraded", "reason", why, "note",
			"absence of alerts from a degraded scan does not mean absence of opportunities")
	}
}

// WarnSourceError logs a per-item source failure at a level that will not drown
// the summary line.
func (l *Logger) WarnSourceError(phase string, err error) {
	l.Warn("source error", "phase", phase, "error", err.Error())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ContextWithScan attaches a scan ID to a context so that log lines from
// concurrent work can be correlated.
func ContextWithScan(ctx context.Context, scanID string) context.Context {
	return context.WithValue(ctx, scanKey{}, scanID)
}

// ScanIDFromContext returns the scan ID, or "" when absent.
func ScanIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(scanKey{}).(string); ok {
		return v
	}
	return ""
}

type scanKey struct{}
