package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/alerts"

	"github.com/eadeshina/hunter/internal/domain"

	"github.com/eadeshina/hunter/internal/pipeline"
)

// sampleSubjectPrefix marks a message as not a real alert.
//
// Without it a sample could be mistaken for a genuine opportunity, and a
// researcher who receives one would reasonably start working a program on the
// strength of it.
const sampleSubjectPrefix = "SAMPLE - NOT A REAL OPPORTUNITY: "

// cmdTestEmail sends one rendered example so the layout can be checked in the
// recipient's own mail client.
//
// The channel's only output is an email, and it may be days before a qualifying
// launch appears. Verifying that the message renders, that the plain-text
// fallback is readable, and that dark mode looks right is otherwise impossible
// until the first real alert, which is the worst possible time to discover a
// broken template.
func cmdTestEmail(env *Env, args []string) int {
	var (
		common commonFlags
		id     string
	)
	fs := flag.NewFlagSet("test-email", flag.ContinueOnError)
	common.register(fs)
	if !parseFlags(fs, env, args) {
		return exitFailure
	}
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: hunter test-email [program-id]")
		fmt.Fprintln(env.Stderr, "Sends one rendered example so the email layout can be checked.")
		fmt.Fprintln(env.Stderr, "With no id, the highest-priority eligible program is used.")
	}
	if fs.NArg() > 0 {
		id = fs.Arg(0)
	}

	profile, store, logger, err := common.buildEnv(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "test-email: %v\n", err)
		return classifyConfigError(err)
	}

	q := pipeline.NewQuery(profile, store, env.Now)
	ev, ok, err := sampleCandidate(q, id)
	if err != nil {
		fmt.Fprintf(env.Stderr, "test-email: %v\n", err)
		return exitFailure
	}
	if !ok {
		fmt.Fprintln(env.Stderr, "test-email: no eligible program found to render; run a scan first")
		return exitFailure
	}

	// The alert is rendered by the production renderer, so the sample exercises
	// the same code path a real alert takes.
	now := env.Now()
	launchAge := 3*time.Hour + 12*time.Minute
	cand := alerts.Candidate{
		Program:  ev.Program,
		Diff:     ev.Diff,
		Decision: ev.Decision,
		Triage:   ev.Triage,
		Fresh:    ev.Fresh,
		Prior:    ev.Prior,
	}
	// Present the chosen program as freshly launched, because that is the state
	// every real alert is in and therefore the state the template is built for.
	launchedAt := now.Add(-launchAge)
	sample := ev.Program
	sample.StartedAt = &launchedAt
	sample.Finalize()
	cand.Program = sample

	subject, body, htmlBody := alerts.Render(cand, profile, now)
	subject = sampleSubjectPrefix + strings.TrimPrefix(subject, sampleSubjectPrefix)

	alert := domain.Alert{
		Fingerprint: "sample-" + now.Format("20060102T150405Z"),
		Kind:        domain.AlertNewQualifying,
		ProgramID:   sample.ID,
		Program:     sample,
		Decision:    ev.Decision,
		Triage:      ev.Triage,
		Subject:     subject,
		Body:        body,
		HTMLBody:    htmlBody,
		DetectedAt:  now,
		ScanID:      "sample",
	}

	if common.asJSON {
		return emitJSON(env, map[string]any{
			"sent":    false,
			"subject": subject,
			"note":    "rendered only; nothing was sent",
		})
	}

	notifier := newNotifier(env)()
	if notifier == nil {
		fmt.Fprintln(env.Stderr, "test-email: no delivery channel is configured; rendering only")
		fmt.Fprintf(env.Stdout, "\nSubject: %s\n\n%s\n", subject, body)
		return exitOK
	}

	if err := notifier.Send(context.Background(), alert); err != nil {
		fmt.Fprintf(env.Stderr, "test-email: %v\n", err)
		return exitFailure
	}

	logger.Info("sample alert sent", "program", sample.Name, "subject", subject)
	fmt.Fprintf(env.Stdout, "Sample alert sent for %q to %s.\n", sample.Name, profile.Name)
	fmt.Fprintf(env.Stdout, "The subject is marked as a sample so it cannot be mistaken for a real opportunity.\n")
	return exitOK
}

// sampleCandidate picks a program to render, preferring a named one.
func sampleCandidate(q *pipeline.Query, id string) (pipeline.Evaluated, bool, error) {
	ctx := context.Background()
	if id != "" {
		ev, ok, err := q.Explain(ctx, id)
		return ev, ok, err
	}
	rows, err := q.Programs(ctx, pipeline.ProgramRequest{Eligible: true, Limit: 1})
	if err != nil {
		return pipeline.Evaluated{}, false, err
	}
	if len(rows) == 0 {
		return pipeline.Evaluated{}, false, nil
	}
	return rows[0], true, nil
}
