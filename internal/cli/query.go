package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
)

// writeJSON writes a value as indented JSON.
//
// HTML escaping is disabled because program descriptions legitimately contain
// <, > and &, and escaping them would corrupt the recorded evidence.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// newQuery builds a query surface from flags.
func (c *commonFlags) newQuery(env *Env) (*pipeline.Query, error) {
	profile, store, logger, err := c.buildEnv(env)
	if err != nil {
		return nil, err
	}
	_ = logger
	return pipeline.NewQuery(profile, store, env.Now), nil
}

// cmdPrograms lists programs recorded in state.
func cmdPrograms(env *Env, args []string) int {
	var (
		common   commonFlags
		eligible bool
		isNew    bool
		changed  bool
		source   string
		limit    int
	)
	fs := flag.NewFlagSet("programs", flag.ContinueOnError)
	common.register(fs)
	fs.BoolVar(&eligible, "eligible", false, "only programs the profile accepts")
	fs.BoolVar(&isNew, "new", false, "only programs first seen in the last scan")
	fs.BoolVar(&changed, "changed", false, "only programs changed in the last scan")
	fs.StringVar(&source, "source", "", "filter by source name")
	fs.IntVar(&limit, "limit", 0, "maximum rows")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "programs: %v\n", err)
		return classifyConfigError(err)
	}

	rows, err := q.Programs(context.Background(), pipeline.ProgramRequest{
		Eligible: eligible, New: isNew, Changed: changed, Source: source, Limit: limit,
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "programs: %v\n", err)
		return exitFailure
	}

	snap, err := q.Snapshot(context.Background())
	if err != nil {
		fmt.Fprintf(env.Stderr, "programs: %v\n", err)
		return exitFailure
	}

	if common.asJSON {
		return emitJSON(env, map[string]any{
			"profile":  q.Profile().Name,
			"scan_id":  snap.LastScanID,
			"count":    len(rows),
			"programs": buildProgramSummaries(rows),
		})
	}

	renderProgramTable(env.Stdout, rows, snap)
	return exitOK
}

// renderProgramTable writes the human-readable program listing.
func renderProgramTable(w io.Writer, rows []pipeline.Evaluated, snap *state.Snapshot) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "No programs match.")
		fmt.Fprintf(w, "State directory holds %d program(s); last scan %s.\n",
			len(snap.Programs), scanLabel(snap.LastScanID))
		return
	}

	fmt.Fprintf(w, "%-44s %-8s %5s %7s %-14s %-5s %s\n",
		"PROGRAM", "STATE", "SCORE", "AGE", "CRYPTO", "OK", "SURFACES")
	for _, e := range rows {
		age := ""
		if e.Fresh.FirstSeenAge > 0 {
			age = domain.HumanizeDuration(e.Fresh.FirstSeenAge)
		}
		crypto := string(e.Program.CryptoKind)
		if crypto == "" || crypto == string(domain.CryptoNotCrypto) {
			crypto = "-"
		}
		mark := "no"
		if e.Decision.Eligible {
			mark = "yes"
		}
		surfaces := e.Program.SurfaceTags.Join()
		if surfaces == "" {
			surfaces = "-"
		}
		fmt.Fprintf(w, "%-44s %-8s %5d %7s %-14s %-5s %s\n",
			truncate(e.Program.Name, 44), string(e.Program.State),
			e.Triage.Total, age, truncate(crypto, 14), mark, truncate(surfaces, 40))
	}
	fmt.Fprintf(w, "\n%d program(s) shown; last scan %s.\n", len(rows), scanLabel(snap.LastScanID))
}

func scanLabel(id string) string {
	if id == "" {
		return "never"
	}
	return id
}

// cmdExplain shows the full eligibility decision for one program.
func cmdExplain(env *Env, args []string) int {
	var common commonFlags
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	common.register(fs)
	if !parseFlags(fs, env, args) {
		return exitFailure
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(env.Stderr, "explain: a program id or slug is required")
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "explain: %v\n", err)
		return classifyConfigError(err)
	}

	ev, ok, err := q.Explain(context.Background(), fs.Arg(0))
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("no program matching %q", fs.Arg(0))
		}
		fmt.Fprintf(env.Stderr, "explain: %v\n", err)
		return exitFailure
	}

	if common.asJSON {
		return emitJSON(env, explainPayload(q, ev))
	}
	renderExplain(env.Stdout, q, ev)
	return exitOK
}

// explainPayload builds the machine-readable explanation.
func explainPayload(q *pipeline.Query, ev pipeline.Evaluated) map[string]any {
	p := ev.Program
	return map[string]any{
		"profile": q.Profile().Name,
		"program": map[string]any{
			"id": p.ID, "name": p.Name, "source": p.Source, "url": p.URL,
			"state": p.State, "raw_status": p.RawStatus,
			"reputation": p.Reputation, "fee": p.Fee, "kyc": p.KYC, "poc": p.POC,
			"surfaces": p.SurfaceTags, "capabilities": p.CapabilityTags,
			"crypto_kind": p.CryptoKind, "crypto_traits": p.CryptoTraits,
			"parse_confidence": p.ParseConfidence, "parse_issues": p.ParseIssues,
			"scope_fingerprint":       p.ScopeFingerprint,
			"requirement_fingerprint": p.RequirementFingerprint,
			"metadata_fingerprint":    p.MetadataFingerprint,
		},
		"decision":  ev.Decision,
		"triage":    ev.Triage,
		"freshness": ev.Fresh,
	}
}

// renderExplain writes the human-readable explanation.
func renderExplain(w io.Writer, q *pipeline.Query, ev pipeline.Evaluated) {
	p := ev.Program
	d := ev.Decision

	fmt.Fprintf(w, "Program:   %s\n", p.Name)
	fmt.Fprintf(w, "ID:        %s\n", p.ID)
	fmt.Fprintf(w, "Source:    %s\n", p.Source)
	if p.URL != "" {
		fmt.Fprintf(w, "URL:       %s\n", p.URL)
	}
	fmt.Fprintf(w, "State:     %s (source status %q)\n", p.State, p.RawStatus)
	fmt.Fprintf(w, "Profile:   %s\n", q.Profile().Name)
	fmt.Fprintf(w, "Verdict:   %s\n", eligibleWord(d.Eligible))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Access:")
	fmt.Fprintf(w, "  reputation:       %s\n", explainReputation(p.Reputation))
	fmt.Fprintf(w, "  kyc:              %s\n", p.KYC)
	fmt.Fprintf(w, "  submission fee:   %s\n", explainFee(p.Fee))
	fmt.Fprintf(w, "  proof of concept: %s\n", p.POC)
	if p.MaxBountyUSD != nil {
		fmt.Fprintf(w, "  bounty ceiling:   $%.0f\n", *p.MaxBountyUSD)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Attack surface:")
	if len(p.SurfaceTags) == 0 {
		fmt.Fprintln(w, "  none detected")
	} else {
		fmt.Fprintf(w, "  %s\n", p.SurfaceTags.Join())
	}
	if len(p.CapabilityTags) > 0 {
		fmt.Fprintf(w, "  capabilities: %s\n", p.CapabilityTags.Join())
	}
	for _, t := range p.Targets {
		mark := "+"
		if !t.InScope {
			mark = "-"
		}
		fmt.Fprintf(w, "  %s [%s] %s\n", mark, t.Kind, t.Identifier)
	}
	fmt.Fprintln(w)

	if p.CryptoKind != "" && p.CryptoKind != domain.CryptoNotCrypto {
		fmt.Fprintln(w, "Crypto classification:")
		fmt.Fprintf(w, "  kind:   %s\n", p.CryptoKind)
		if len(p.CryptoTraits) > 0 {
			fmt.Fprintf(w, "  traits: %s\n", p.CryptoTraits.Join())
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Parse confidence: %s\n", p.ParseConfidence)
	for _, issue := range p.ParseIssues {
		fmt.Fprintf(w, "  issue: %s\n", issue)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Policy checks:")
	for _, c := range d.Checks {
		fmt.Fprintf(w, "  [%-4s] %s\n", checkMark(c.Outcome), c.ID)
		fmt.Fprintf(w, "          %s\n", c.Reason())
		if c.Detail != "" && c.Outcome != domain.CheckPass {
			fmt.Fprintf(w, "          detail: %s\n", c.Detail)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Attention priority: %d/100 (ordering aid, not a success estimate)\n", ev.Triage.Total)
	for _, c := range ev.Triage.Components {
		fmt.Fprintf(w, "  %-20s %3d  %s\n", c.Name, c.Value, c.Basis)
	}
	if lines := ev.Fresh.AgeStrings(); len(lines) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Timing:")
		for _, l := range lines {
			fmt.Fprintf(w, "  %s\n", l)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Fingerprints:")
	fmt.Fprintf(w, "  scope:        %s\n", shortHash(p.ScopeFingerprint))
	fmt.Fprintf(w, "  requirements: %s\n", shortHash(p.RequirementFingerprint))
	fmt.Fprintf(w, "  metadata:     %s\n", shortHash(p.MetadataFingerprint))
}

func checkMark(o domain.CheckOutcome) string {
	switch o {
	case domain.CheckPass:
		return "pass"
	case domain.CheckFail:
		return "FAIL"
	case domain.CheckUnknown:
		return "UNKN"
	default:
		return "skip"
	}
}

func eligibleWord(eligible bool) string {
	if eligible {
		return "ELIGIBLE"
	}
	return "NOT ELIGIBLE"
}

func explainReputation(g domain.ReputationGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("%d points required", g.Points)
	case domain.TriNo:
		return "none required"
	default:
		return "UNKNOWN"
	}
}

func explainFee(g domain.FeeGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("$%.2f", g.USD)
	case domain.TriNo:
		return "none"
	default:
		return "UNKNOWN"
	}
}

// shortHash renders a fingerprint for display without implying it is a full
// identifier.
func shortHash(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

// cmdHistory shows recorded changes for one program.
func cmdHistory(env *Env, args []string) int {
	var common commonFlags
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	common.register(fs)
	if !parseFlags(fs, env, args) {
		return exitFailure
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(env.Stderr, "history: a program id or slug is required")
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "history: %v\n", err)
		return classifyConfigError(err)
	}

	id, entries, err := q.History(context.Background(), fs.Arg(0))
	if err != nil {
		fmt.Fprintf(env.Stderr, "history: %v\n", err)
		return exitFailure
	}

	if common.asJSON {
		return emitJSON(env, map[string]any{
			"program_id": id,
			"count":      len(entries),
			"entries":    entries,
		})
	}

	if len(entries) == 0 {
		fmt.Fprintf(env.Stdout, "No recorded material changes for %s.\n", id)
		return exitOK
	}

	fmt.Fprintf(env.Stdout, "Change history for %s (%d entries, oldest first):\n\n", id, len(entries))
	for _, e := range entries {
		fmt.Fprintf(env.Stdout, "%s  eligible=%v\n", e.At.UTC().Format(time.RFC3339), e.Eligible)
		for _, c := range e.Changes {
			fmt.Fprintf(env.Stdout, "    %s\n", c.Describe())
		}
		if len(e.Reasons) > 0 {
			fmt.Fprintf(env.Stdout, "    reasons: %s\n", strings.Join(nonEmpty(e.Reasons), "; "))
		}
		fmt.Fprintln(env.Stdout)
	}
	return exitOK
}

// cmdAlerts lists recorded alerts.
func cmdAlerts(env *Env, args []string) int {
	var (
		common      commonFlags
		undelivered bool
		limit       int
	)
	fs := flag.NewFlagSet("alerts", flag.ContinueOnError)
	common.register(fs)
	fs.BoolVar(&undelivered, "undelivered", false, "only alerts not confirmed delivered")
	fs.IntVar(&limit, "limit", 50, "maximum rows")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	q, err := common.newQuery(env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "alerts: %v\n", err)
		return classifyConfigError(err)
	}

	records, err := q.Alerts(context.Background(), undelivered, limit)
	if err != nil {
		fmt.Fprintf(env.Stderr, "alerts: %v\n", err)
		return exitFailure
	}

	if common.asJSON {
		return emitJSON(env, map[string]any{"count": len(records), "alerts": records})
	}

	if len(records) == 0 {
		fmt.Fprintln(env.Stdout, "No alerts recorded.")
		return exitOK
	}

	fmt.Fprintf(env.Stdout, "%-22s %-18s %-9s %5s  %s\n", "WHEN", "KIND", "STATUS", "TRIES", "SUBJECT")
	for _, r := range records {
		status := "delivered"
		if !r.Delivered {
			status = "PENDING"
		}
		fmt.Fprintf(env.Stdout, "%-22s %-18s %-9s %5d  %s\n",
			r.CreatedAt.UTC().Format(time.RFC3339), string(r.Kind), status, r.Attempts, r.Subject)
		if r.LastError != "" {
			fmt.Fprintf(env.Stdout, "%-22s last error: %s\n", "", r.LastError)
		}
	}
	fmt.Fprintf(env.Stdout, "\n%d alert(s).\n", len(records))
	return exitOK
}

// emitJSON writes a value and maps the failure onto an exit code.
func emitJSON(env *Env, v any) int {
	if err := writeJSON(env.Stdout, v); err != nil {
		fmt.Fprintf(env.Stderr, "%v\n", err)
		return exitFailure
	}
	return exitOK
}

// cmdValidateConfig parses and validates the profile.
func cmdValidateConfig(env *Env, args []string) int {
	var common commonFlags
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	common.register(fs)
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	profile, err := config.Load(common.profilePath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "profile is invalid: %v\n", err)
		return exitBadConfig
	}

	if common.asJSON {
		return emitJSON(env, map[string]any{
			"valid":                true,
			"path":                 common.profilePath,
			"profile":              profile.Name,
			"sources":              profile.EnabledSources(),
			"allowed_states":       profile.AllowedStates(),
			"crypto_mode":          string(profile.CryptoModeOrDefault()),
			"crypto_allowed":       profile.AllowedCryptoTraits(),
			"crypto_excluded":      profile.ExcludedCryptoTraits(),
			"target_domains":       profile.TargetDomains.Included,
			"max_reputation":       profile.Access.MaxReputationPoints,
			"max_fee_usd":          profile.Access.MaxSubmissionFeeUSD,
			"kyc_required":         profile.Access.KYCRequired,
			"accept_unknown_gates": profile.Access.AcceptUnknownAccessGates,
			"min_severity":         string(profile.MinSeverity()),
			"notifications":        profile.Notifications.Enabled,
		})
	}

	fmt.Fprintf(env.Stdout, "Profile is valid.\n\n")
	fmt.Fprintf(env.Stdout, "  name:                 %s\n", profile.Name)
	fmt.Fprintf(env.Stdout, "  sources:              %v\n", profile.EnabledSources())
	fmt.Fprintf(env.Stdout, "  accepted states:      %v\n", profile.AllowedStates())
	fmt.Fprintf(env.Stdout, "  crypto mode:          %s\n", profile.CryptoModeOrDefault())
	fmt.Fprintf(env.Stdout, "  crypto allowed:       %s\n", profile.AllowedCryptoTraits().Tags().Join())
	fmt.Fprintf(env.Stdout, "  crypto excluded:      %s\n", profile.ExcludedCryptoTraits().Tags().Join())
	fmt.Fprintf(env.Stdout, "  target domains:       %v\n", profile.TargetDomains.Included)
	fmt.Fprintf(env.Stdout, "  max reputation:       %d\n", profile.Access.MaxReputationPoints)
	fmt.Fprintf(env.Stdout, "  max submission fee:   $%.2f\n", profile.Access.MaxSubmissionFeeUSD)
	fmt.Fprintf(env.Stdout, "  kyc required:         %s\n", profile.Access.KYCRequired)
	fmt.Fprintf(env.Stdout, "  accept unknown gates: %v\n", profile.Access.AcceptUnknownAccessGates)
	fmt.Fprintf(env.Stdout, "  min alert severity:   %s\n", profile.MinSeverity())
	fmt.Fprintf(env.Stdout, "  notifications:        %v\n", profile.Notifications.Enabled)
	return exitOK
}
