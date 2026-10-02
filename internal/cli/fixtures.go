package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/normalize"
	"github.com/eadeshina/hunter/internal/policy"
	"github.com/eadeshina/hunter/internal/source"
	"github.com/eadeshina/hunter/internal/source/hackenproof"
)

// fixtureDir is where captured pages live.
const fixtureDir = "fixtures/hackenproof"

// cmdTestFixtures re-parses the checked-in fixtures.
//
// This is the offline counterpart to a live scan. It exercises the real adapter
// against recorded upstream output, which is what makes "the parser is verified"
// a meaningful statement: the bytes being checked will not change when the
// upstream site does.
func cmdTestFixtures(env *Env, args []string) int {
	var (
		common commonFlags
		dir    string
	)
	fs := flag.NewFlagSet("test-fixtures", flag.ContinueOnError)
	common.register(fs)
	fs.StringVar(&dir, "fixtures", fixtureDir, "fixture directory")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	profile, err := config.Load(common.profilePath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "test-fixtures: %v\n", err)
		return exitBadConfig
	}

	names, err := fixtureFiles(dir)
	if err != nil {
		fmt.Fprintf(env.Stderr, "test-fixtures: %v\n", err)
		return exitFailure
	}

	results := make([]fixtureReport, 0, len(names))
	failures := 0
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(env.Stderr, "test-fixtures: %v\n", err)
			return exitFailure
		}
		rep := runFixture(profile, body, name)
		if !rep.Parsed {
			failures++
		}
		results = append(results, rep)
	}

	if common.asJSON {
		if err := writeJSON(env.Stdout, map[string]any{
			"fixtures": len(results),
			"failed":   failures,
			"results":  results,
		}); err != nil {
			fmt.Fprintf(env.Stderr, "test-fixtures: %v\n", err)
			return exitFailure
		}
		if failures > 0 {
			return exitFailure
		}
		return exitOK
	}

	fmt.Fprintf(env.Stdout, "Parsed %d fixture(s) from %s\n\n", len(results), dir)
	for _, r := range results {
		status := "ok    "
		if !r.Parsed {
			status = "FAILED"
		}
		fmt.Fprintf(env.Stdout, "[%s] %s (%s)\n", status, r.File, r.Kind)
		if r.Parsed {
			if r.Program != "" {
				fmt.Fprintf(env.Stdout, "        program      %s\n", r.Program)
			}
			if r.Discovered > 0 {
				fmt.Fprintf(env.Stdout, "        discovered   %d program(s)\n", r.Discovered)
				for _, s := range r.Samples {
					fmt.Fprintf(env.Stdout, "                     - %s\n", s)
				}
			}
			for _, k := range sortedKeys(r.Access) {
				fmt.Fprintf(env.Stdout, "        %-12s %s\n", k, r.Access[k])
			}
			if len(r.Surfaces) > 0 {
				fmt.Fprintf(env.Stdout, "        %-12s %s\n", "surfaces", strings.Join(r.Surfaces, ", "))
			}
			fmt.Fprintf(env.Stdout, "        %-12s %d\n", "targets", r.Targets)
			if r.Crypto != "" {
				fmt.Fprintf(env.Stdout, "        %-12s %s\n", "crypto", r.Crypto)
			}
			if r.Eligible != nil {
				mark := "no"
				if *r.Eligible {
					mark = "yes"
				}
				fmt.Fprintf(env.Stdout, "        %-12s %s\n", "eligible", mark)
			}
		}
		for _, issue := range r.Issues {
			fmt.Fprintf(env.Stdout, "        issue        %s\n", issue)
		}
	}
	fmt.Fprintln(env.Stdout)

	if failures > 0 {
		fmt.Fprintf(env.Stdout, "%d of %d fixture(s) failed to parse.\n", failures, len(results))
		return exitFailure
	}
	fmt.Fprintf(env.Stdout, "All %d fixture(s) parsed successfully.\n", len(results))
	fmt.Fprintln(env.Stdout, "This validates parsing only. Use `hunter scan` against the live source to validate end to end.")
	return exitOK
}

// fixtureFiles lists captured pages in a stable order.
func fixtureFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no .html fixtures found in %s", dir)
	}
	sort.Strings(names)
	return names, nil
}

// fixtureReport is the structured result for one fixture.
type fixtureReport struct {
	File       string            `json:"file"`
	Kind       string            `json:"kind"`
	Program    string            `json:"program,omitempty"`
	Discovered int               `json:"discovered,omitempty"`
	Samples    []string          `json:"samples,omitempty"`
	Parsed     bool              `json:"parsed"`
	Issues     []string          `json:"issues,omitempty"`
	Access     map[string]string `json:"access,omitempty"`
	Surfaces   []string          `json:"surfaces,omitempty"`
	Targets    int               `json:"targets"`
	Crypto     string            `json:"crypto_kind,omitempty"`
	Eligible   *bool             `json:"eligible,omitempty"`
	Reasons    []string          `json:"reasons,omitempty"`
}

// isListingFixture distinguishes a listing page from a detail page by filename,
// which avoids adding a manifest file for two fixtures' worth of metadata.
func isListingFixture(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "listing")
}

// fixtureNow is a fixed clock so that fixture evaluation is reproducible.
var fixtureNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// runFixture parses one fixture through the real adapter and evaluates it.
func runFixture(profile *config.Profile, body []byte, name string) fixtureReport {
	if isListingFixture(name) {
		return runListingFixture(body, name)
	}
	return runProgramFixture(profile, body, name)
}

func runListingFixture(body []byte, name string) fixtureReport {
	rep := fixtureReport{File: name, Kind: "listing"}
	refs, err := hackenproof.ParseListingPage(body)
	if err != nil {
		rep.Issues = append(rep.Issues, err.Error())
		return rep
	}
	rep.Parsed = true
	rep.Discovered = len(refs)
	for i, r := range refs {
		if i >= 5 {
			break
		}
		label := r.Slug
		if r.SubmittedReportsKnown && r.SubmittedReports != nil {
			label += fmt.Sprintf(" (%d submissions)", *r.SubmittedReports)
		}
		rep.Samples = append(rep.Samples, label)
	}
	return rep
}

func runProgramFixture(profile *config.Profile, body []byte, name string) fixtureReport {
	rep := fixtureReport{File: name, Kind: "program"}

	slug := strings.TrimSuffix(name, filepath.Ext(name))
	ref := domain.ProgramRef{
		Source: hackenproof.AdapterName, ID: slug, Slug: slug,
		URL: hackenproof.DefaultBaseURL + "/programs/" + slug,
	}

	raw, err := hackenproof.ParseProgramPage(body, ref)
	if err != nil {
		rep.Issues = append(rep.Issues, err.Error())
		return rep
	}
	if !raw.Parsed {
		rep.Issues = append(rep.Issues, raw.Issues...)
		return rep
	}

	program := normalize.Program(raw, normalize.Options{Now: func() time.Time { return fixtureNow }})
	rep.Parsed = true
	rep.Program = program.Name
	rep.Issues = append(rep.Issues, program.ParseIssues...)
	rep.Surfaces = program.SurfaceTags
	rep.Targets = len(program.Targets)
	rep.Crypto = string(program.CryptoKind)
	rep.Access = map[string]string{
		"state":       string(program.State),
		"raw status":  program.RawStatus,
		"reputation":  describeGate(program.Reputation),
		"kyc":         program.KYC.String(),
		"fee":         describeFeeGate(program.Fee),
		"poc":         program.POC.String(),
		"max bounty":  describeBounty(program),
		"submissions": describeSubmissions(program),
		"confidence":  string(program.ParseConfidence),
	}

	decision := policy.New(profile, func() time.Time { return fixtureNow }).Evaluate(program)
	rep.Eligible = &decision.Eligible
	rep.Reasons = decision.Reasons
	return rep
}

func describeGate(g domain.ReputationGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("%d points required", g.Points)
	case domain.TriNo:
		return "none required"
	default:
		return "UNKNOWN"
	}
}

func describeFeeGate(g domain.FeeGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("$%.2f", g.USD)
	case domain.TriNo:
		return "none"
	default:
		return "UNKNOWN"
	}
}

func describeBounty(p domain.Program) string {
	if p.MaxBountyUSD == nil {
		return "unstated"
	}
	return fmt.Sprintf("$%.0f", *p.MaxBountyUSD)
}

func describeSubmissions(p domain.Program) string {
	if !p.SubmittedReportsKnown || p.SubmittedReports == nil {
		return "not published"
	}
	return fmt.Sprintf("%d reported", *p.SubmittedReports)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ensure source stays referenced by the parse-error wording contract.
var _ = source.ErrParse
