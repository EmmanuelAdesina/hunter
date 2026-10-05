package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
)

// cmdReplay merges saved change history and opportunity windows into a
// chronological, read-only timeline.
func cmdReplay(env *Env, args []string) int {
	var (
		common commonFlags
		limit  int
	)
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	common.register(fs)
	fs.IntVar(&limit, "limit", 200, "maximum timeline events; zero means unlimited")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(env.Stderr, "replay: exactly one program id or slug is required")
		return exitFailure
	}
	if limit < 0 {
		fmt.Fprintln(env.Stderr, "replay: --limit must be >= 0")
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "replay: %v\n", err)
		return classifyConfigError(err)
	}
	timeline, err := q.Replay(context.Background(), fs.Arg(0), limit)
	if err != nil {
		fmt.Fprintf(env.Stderr, "replay: %v\n", err)
		return exitFailure
	}
	if common.asJSON {
		return emitJSON(env, timeline)
	}
	renderReplay(env.Stdout, timeline, q.Now())
	return exitOK
}

// renderReplay presents the recorded timeline without assigning a point time to
// an observed interval or re-evaluating historical decisions.
func renderReplay(w io.Writer, timeline pipeline.ReplayTimeline, now time.Time) {
	if timeline.Total == 0 {
		fmt.Fprintf(w, "No recorded changes or opportunity windows for %s.\n", timeline.ProgramID)
		return
	}
	fmt.Fprintf(w,
		"Saved timeline for %s (%d of %d event(s); earliest evidence first; intervals remain bounded; past decisions are not re-evaluated):\n",
		timeline.ProgramID, timeline.Count, timeline.Total)

	for i, event := range timeline.Events {
		fmt.Fprintf(w, "\nEVENT %d [%s]\n", i+1, strings.ToUpper(event.Kind))
		if event.RecordedAt != nil {
			fmt.Fprintf(w, "Recorded at: %s\n", event.RecordedAt.UTC().Format(time.RFC3339))
		}
		if event.ScanID != "" {
			fmt.Fprintf(w, "Scan: %s\n", event.ScanID)
		}
		if event.Eligible != nil {
			fmt.Fprintf(w, "Eligibility recorded: %t\n", *event.Eligible)
		}
		for _, change := range event.Changes {
			fmt.Fprintf(w, "  %s\n", change.Describe())
		}
		for _, reason := range event.Reasons {
			if strings.TrimSpace(reason) != "" {
				fmt.Fprintf(w, "  reason: %s\n", reason)
			}
		}
		for _, window := range event.Windows {
			renderReplayWindow(w, window, now)
		}
	}
}

func renderReplayWindow(w io.Writer, window domain.OpportunityWindow, now time.Time) {
	fmt.Fprintf(w, "Opportunity window %s:\n", window.ShortID())
	if window.Observed.Known() {
		fmt.Fprintf(w, "  Observed interval: %s\n", window.Observed.Humanize(now))
	} else {
		fmt.Fprintln(w, "  Observed interval: unknown")
	}
	if len(window.Deltas) == 0 {
		fmt.Fprintln(w, "  Atomic deltas: (none stored)")
	} else {
		fmt.Fprintln(w, "  Atomic deltas:")
		for _, delta := range window.Deltas {
			fmt.Fprintf(w, "    %s\n", delta.Describe())
		}
	}
	if window.BaselineSubmissions != nil || window.CurrentSubmissions != nil ||
		window.SubmissionsSinceOpen != nil {
		movement := "unknown"
		if window.SubmissionsSinceOpen != nil {
			movement = fmt.Sprintf("%+d", *window.SubmissionsSinceOpen)
		}
		fmt.Fprintf(w, "  Submissions reported: baseline %s; current %s; change %s\n",
			countOrUnknown(window.BaselineSubmissions),
			countOrUnknown(window.CurrentSubmissions), movement)
	}
}
