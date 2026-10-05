package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/pipeline"
)

// cmdWindows lists opportunity windows recorded by scans.
func cmdWindows(env *Env, args []string) int {
	var (
		common   commonFlags
		openOnly bool
		program  string
		limit    int
	)
	fs := flag.NewFlagSet("windows", flag.ContinueOnError)
	common.register(fs)
	fs.BoolVar(&openOnly, "open", false, "only windows that remain open")
	fs.StringVar(&program, "program", "", "filter by program ID, slug, or unambiguous name")
	fs.IntVar(&limit, "limit", 50, "maximum rows")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "windows: %v\n", err)
		return classifyConfigError(err)
	}

	rows, err := q.Windows(context.Background(), pipeline.WindowsRequest{
		OpenOnly: openOnly,
		Program:  program,
		Limit:    limit,
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "windows: %v\n", err)
		return exitFailure
	}
	if common.asJSON {
		return emitJSON(env, map[string]any{"count": len(rows), "windows": rows})
	}
	renderWindows(env.Stdout, rows, q.Now())
	return exitOK
}

// renderWindows writes opportunity windows newest first.
func renderWindows(w io.Writer, rows []pipeline.WindowView, now time.Time) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "No opportunity windows match.")
		return
	}
	for i, row := range rows {
		if i > 0 {
			fmt.Fprintln(w)
		}
		writeWindow(w, row, now)
	}
	fmt.Fprintf(w, "\n%d window(s).\n", len(rows))
}

// writeWindow renders the temporal bound, status, and each atomic delta. A
// window groups evidence; it does not replace the individual changes with an
// editorial summary.
func writeWindow(w io.Writer, row pipeline.WindowView, now time.Time) {
	window := row.Window
	fmt.Fprintf(w, "RESEARCH WINDOW %s [%s]\n", window.ShortID(), strings.ToUpper(string(row.Status)))
	if window.ProgramName != "" {
		fmt.Fprintf(w, "Program: %s (%s)\n", window.ProgramName, window.ProgramID)
	} else {
		fmt.Fprintf(w, "Program: %s\n", window.ProgramID)
	}

	// Eligibility is evaluated at query time, so it reflects the current profile.
	// An open window on an ineligible program is still a valid window - it just
	// isn't actionable for this researcher.
	if row.Eligible {
		fmt.Fprintln(w, "Eligibility: eligible")
	} else {
		fmt.Fprintln(w, "Eligibility: not eligible")
		if len(row.EligReas) > 0 {
			fmt.Fprintln(w, "  Reasons:")
			for _, r := range row.EligReas {
				fmt.Fprintf(w, "    - %s\n", r)
			}
		}
	}

	if window.Observed.Known() {
		fmt.Fprintf(w, "Observed: %s\n", window.Observed.Humanize(now))
	} else {
		fmt.Fprintln(w, "Observed: unknown (expired)")
	}
	if len(window.Triggers) > 0 {
		fmt.Fprintf(w, "Triggers: %s\n", strings.Join(window.Triggers, ", "))
	}
	if window.OpenedScanID != "" {
		fmt.Fprintf(w, "Opened by scan: %s\n", window.OpenedScanID)
	}

	fmt.Fprintln(w, "Atomic changes:")
	if len(window.Deltas) == 0 {
		fmt.Fprintln(w, "  (no delta evidence stored)")
	} else {
		for _, delta := range window.Deltas {
			fmt.Fprintf(w, "  %s\n", delta.Describe())
		}
	}

	if window.BaselineSubmissions != nil || window.CurrentSubmissions != nil ||
		window.SubmissionsSinceOpen != nil {
		baseline := countOrUnknown(window.BaselineSubmissions)
		current := countOrUnknown(window.CurrentSubmissions)
		movement := "unknown"
		if window.SubmissionsSinceOpen != nil {
			movement = fmt.Sprintf("%+d", *window.SubmissionsSinceOpen)
		}
		fmt.Fprintf(w, "Submissions reported: baseline %s; current %s; change %s\n",
			baseline, current, movement)
	}
}

func countOrUnknown(v *int) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v)
}
