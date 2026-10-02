// Package pipeline orchestrates a scan.
//
// The sequence is fixed and each stage is isolated: a failure in one program
// cannot end the scan, and a failure in one source cannot prevent another source
// from being processed. The ordering is deliberate and matches the mandate:
//
//	discover -> fetch -> normalize -> diff -> policy -> score -> alert -> send -> persist
//
// State is persisted before notification is attempted. That ordering is what
// makes a crash mid-delivery recoverable: the alert exists in state with its
// fingerprint, so the next run can re-send it without regenerating or
// duplicating it.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/eadeshina/hunter/internal/alerts"
	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/diff"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/normalize"
	"github.com/eadeshina/hunter/internal/notify"
	"github.com/eadeshina/hunter/internal/obs"
	"github.com/eadeshina/hunter/internal/policy"
	"github.com/eadeshina/hunter/internal/scoring"
	"github.com/eadeshina/hunter/internal/source"
	"github.com/eadeshina/hunter/internal/state"
)

// Config wires a scan.
type Config struct {
	Profile *config.Profile
	Sources []domain.ProgramSource
	Store   state.StateStore
	Logger  *obs.Logger

	// Notifier delivers alerts. When nil or unconfigured, alerts are still
	// generated, scored, and recorded; they are simply not transmitted.
	Notifier notify.Notifier

	// Now supplies the current time, keeping scans reproducible in tests.
	Now func() time.Time

	// FetchDetails controls whether detail pages are fetched. Disabling it
	// makes a listing-only run possible at the cost of access-gate accuracy.
	FetchDetails bool

	// DryRun generates, scores, and records alerts without sending them.
	DryRun bool

	// Concurrency bounds parallel detail fetches per source.
	Concurrency int
}

// Result is the outcome of one scan.
type Result struct {
	Metrics obs.ScanMetrics

	// Programs holds every evaluated program with its decision.
	Programs []Evaluated

	// Alerts holds the alerts generated, whether or not they were sent.
	Alerts []domain.Alert

	// Errors collects every non-fatal problem encountered.
	Errors []error
}

// Evaluated is one program's full evaluation.
type Evaluated struct {
	Program  domain.Program
	Diff     domain.Diff
	Decision domain.EligibilityDecision
	Triage   domain.Triage
	Fresh    domain.Freshness
	Prior    alerts.PriorDecision
}

// Eligible reports whether the program matched the profile.
func (e Evaluated) Eligible() bool { return e.Decision.Eligible }

// Scanner runs scans.
type Scanner struct {
	cfg       Config
	policy    *policy.Engine
	detector  *diff.Detector
	generator *alerts.Generator
	scorer    *scoring.Scorer
	normalize normalize.Options
}

// New builds a scanner.
func New(cfg Config) (*Scanner, error) {
	if cfg.Profile == nil {
		return nil, errors.New("pipeline: profile is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("pipeline: state store is required")
	}
	if len(cfg.Sources) == 0 {
		return nil, errors.New("pipeline: at least one source is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = obs.Discard()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = cfg.Profile.Scan.MaxConcurrent
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}

	return &Scanner{
		cfg:       cfg,
		policy:    policy.New(cfg.Profile, cfg.Now),
		detector:  diff.NewDetector(cfg.Now),
		generator: alerts.NewGenerator(cfg.Profile, cfg.Now),
		scorer:    scoring.New(cfg.Profile),
		normalize: normalize.Options{Now: cfg.Now},
	}, nil
}

// ScanIDFor derives a stable, sortable scan identifier from a timestamp.
func ScanIDFor(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

// Scan runs one complete scan.
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	started := s.cfg.Now()
	scanID := ScanIDFor(started)
	ctx = obs.ContextWithScan(ctx, scanID)

	res := Result{Metrics: obs.ScanMetrics{ScanID: scanID, Started: started}}
	log := s.cfg.Logger.With("scan_id", scanID)

	snap, err := s.cfg.Store.Load(ctx)
	if err != nil {
		// A corrupt snapshot is fatal. Continuing would make every known
		// program look new and fire an alert for all of them.
		return res, fmt.Errorf("load state: %w", err)
	}

	var (
		mu            sync.Mutex
		evaluated     []Evaluated
		freshnessByID = map[string]domain.Freshness{}
	)

	// processSource runs one adapter to completion. Failures are contained so
	// that a single broken integration degrades coverage rather than ending the
	// scan.
	for _, src := range s.cfg.Sources {
		metrics, srcEvaluated, srcFresh, srcErrs := s.runSource(ctx, src, snap, log)
		mu.Lock()
		res.Metrics.Discovered += metrics.Discovered
		res.Metrics.Evaluated += metrics.Evaluated
		res.Metrics.Attempted += metrics.Attempted
		res.Metrics.Fetched += metrics.Fetched
		res.Metrics.FetchFailed += metrics.FetchFailed
		res.Metrics.ListingOnly += metrics.Skipped
		res.Metrics.Errors += metrics.Errors
		res.Errors = append(res.Errors, srcErrs...)
		evaluated = append(evaluated, srcEvaluated...)
		for k, v := range srcFresh {
			freshnessByID[k] = v
		}
		mu.Unlock()

		res.Metrics.Source = src.Name()
	}

	// Programs are sorted by identifier so that the resulting state file and the
	// alert order do not depend on completion order.
	sort.SliceStable(evaluated, func(i, j int) bool {
		return evaluated[i].Program.ID < evaluated[j].Program.ID
	})
	res.Programs = evaluated

	// Count outcomes.
	//
	// Changed counts only material changes, which is what "changed" means
	// everywhere else in the system: the query filter, the change history, and
	// the alert triggers. Counting every observed difference here would report
	// four "changed" programs while `programs --changed` correctly listed none,
	// because a moving submission count is an observation rather than a change to
	// scope or requirements.
	for _, e := range evaluated {
		switch {
		case e.Diff.IsNew:
			res.Metrics.New++
		case e.Diff.Material():
			res.Metrics.Changed++
		case !e.Diff.Changes.Empty():
			res.Metrics.MinorChanged++
		}
		if e.Decision.Eligible {
			res.Metrics.Eligible++
		} else {
			res.Metrics.Rejected++
		}
		if e.Program.ParseConfidence == domain.ConfidenceLow {
			res.Metrics.Quarantined++
		}
	}

	// Alert generation.
	generated, suppressed := s.buildAlerts(evaluated)
	res.Alerts = generated
	res.Metrics.AlertsGenerated = len(generated)
	res.Metrics.AlertsSuppressed = suppressed

	// Persist before notifying. An alert that exists in state but was never sent
	// is recoverable; one that was sent but never recorded is not.
	if err := s.persist(ctx, snap, evaluated, res.Metrics); err != nil {
		res.Errors = append(res.Errors, fmt.Errorf("persist state: %w", err))
		res.Metrics.Errors++
	}

	// Delivery. Alerts recorded on an earlier run that were never delivered are
	// retried alongside anything new, because the condition that produced them is
	// no longer new and this scan would not otherwise generate them.
	//
	// Failures are collected into the scan result rather than only logged, so
	// that the run's exit status reflects a delivery outage instead of reporting
	// success.
	batch := generated
	if pending := s.pendingAlerts(ctx); len(pending) > 0 {
		batch = mergeAlerts(generated, pending)
	}
	sent, failed, skipped := s.deliver(ctx, batch)
	res.Metrics.AlertsSent = sent
	res.Metrics.AlertsFailed = failed
	res.Metrics.AlertsSkipped = skipped
	if failed > 0 {
		res.Metrics.Errors += failed
		res.Errors = append(res.Errors,
			fmt.Errorf("%d of %d alert(s) could not be delivered; they remain recorded and will be retried", failed, len(batch)))
	}

	res.Metrics.Duration = s.cfg.Now().Sub(started)
	log.LogSummary(res.Metrics)

	if degraded, why := res.Metrics.Degraded(); degraded {
		res.Errors = append(res.Errors, fmt.Errorf("degraded scan: %s", why))
	}
	return res, errors.Join(res.Errors...)
}

// sourceMetrics accumulates per-source counters.
type sourceMetrics struct {
	Discovered  int
	Evaluated   int
	Fetched     int
	FetchFailed int
	Skipped     int
	Attempted   int
	Errors      int
}

// runSource discovers and evaluates every program from one adapter.
func (s *Scanner) runSource(ctx context.Context, src domain.ProgramSource, snap *state.Snapshot, log *obs.Logger) (sourceMetrics, []Evaluated, map[string]domain.Freshness, []error) {
	var (
		m    sourceMetrics
		errs []error
	)

	log.Info("discovering", "phase", obs.PhaseDiscover, "source", src.Name())

	refs, err := src.Discover(ctx)
	m.Discovered = len(refs)
	if err != nil {
		// Partial discovery is expected during an outage. The references that
		// did arrive are still evaluated.
		m.Errors++
		errs = append(errs, fmt.Errorf("%s: discover: %w", src.Name(), err))
		log.WarnSourceError(obs.PhaseDiscover, err)
	}

	if m.Discovered == 0 {
		return m, nil, nil, errs
	}

	log.Info("discovered programs", "phase", obs.PhaseDiscover, "source", src.Name(), "count", m.Discovered)

	concurrency := s.cfg.Concurrency
	if caps := src.Capabilities(); caps.MaxConcurrent > 0 && caps.MaxConcurrent < concurrency {
		concurrency = caps.MaxConcurrent
	}

	// One outcome is collected per program.

	outcomes := make([]programOutcome, 0, len(refs))
	var (
		wg  sync.WaitGroup
		rmu sync.Mutex
		sem = make(chan struct{}, concurrency)
	)

	for _, ref := range refs {
		// Cancellation between programs stops the scan promptly instead of
		// working through the remaining references.
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ref domain.ProgramRef) {
			defer wg.Done()
			defer func() { <-sem }()

			// A panic inside one program must not end the scan. The stack is
			// carried into the error because "recovered from panic" without a
			// location is close to useless when diagnosing it later.
			defer func() {
				if rec := recover(); rec != nil {
					stack := debug.Stack()
					rmu.Lock()
					m.Errors++
					m.FetchFailed++
					errs = append(errs, fmt.Errorf("%s: panic handling %s: %v\n%s",
						src.Name(), ref.ID, rec, stack))
					rmu.Unlock()
				}
			}()

			outcome, err := s.evaluateOne(ctx, src, ref, snap, log)
			rmu.Lock()
			defer rmu.Unlock()
			// Attempted counts every evaluation started, including the ones
			// that failed. Degradation is judged on the difference between the
			// two, so a failed attempt must not be invisible here.
			m.Attempted++
			if err != nil {
				// A program that was discovered but deliberately not read is
				// neither an error nor a failure: the cheap tier covered it.
				// Counting it as a failure would make every steady run look
				// broken.
				if errors.Is(err, errNotEvaluated) {
					m.Skipped++
					return
				}
				m.Errors++
				if errors.Is(err, source.ErrParse) {
					m.FetchFailed++
				}
				errs = append(errs, err)
				log.WarnSourceError(obs.PhaseFetch, err)
				return
			}
			m.Evaluated++
			if outcome.DetailFetched {
				m.Fetched++
			} else {
				m.Skipped++
			}
			if outcome.Evaluated.Program.ParseConfidence == domain.ConfidenceLow {
				log.Warn("program quarantined", "program", outcome.Evaluated.Program.ID,
					"issues", outcome.Evaluated.Program.ParseIssues)
			}
			outcomes = append(outcomes, outcome)
		}(ref)
	}
	wg.Wait()

	out := make([]Evaluated, 0, len(outcomes))
	fresh := make(map[string]domain.Freshness, len(outcomes))
	for _, r := range outcomes {
		out = append(out, r.Evaluated)
		fresh[r.Evaluated.Program.ID] = r.Freshness
	}
	return m, out, fresh, errs
}

// programOutcome is the result of evaluating one program.
//
// DetailFetched distinguishes a real detail read from a cheap-tier pass, so
// that the summary line reports requests actually made rather than programs
// merely examined.
type programOutcome struct {
	Evaluated     Evaluated
	Freshness     domain.Freshness
	DetailFetched bool
}

// evaluateOne performs the per-program pipeline.
//
// This is where the two-tier read is decided. Every program is seen through the
// cheap listing sweep; the expensive detail page is fetched only when the
// listing reports something different, when the record has never been completed,
// or when the refresh interval has elapsed. Reading every detail page on a
// five-minute cadence would mean thousands of requests an hour against a
// third-party site, in exchange for access gates that change rarely.
func (s *Scanner) evaluateOne(ctx context.Context, src domain.ProgramSource, ref domain.ProgramRef, snap *state.Snapshot, log *obs.Logger) (programOutcome, error) {
	prev, hadPrev := snap.Program(ref.Key())

	if !s.cfg.FetchDetails || !s.needsDetail(ref, prev, hadPrev) {
		out, err := s.evaluateListingOnly(ref, prev, hadPrev)
		return programOutcome{Evaluated: out, Freshness: out.Fresh}, err
	}

	raw, err := src.Fetch(ctx, ref)
	if err != nil {
		return programOutcome{}, fmt.Errorf("%s: fetch %s: %w", src.Name(), ref.ID, err)
	}
	// A record the adapter could not parse is not evaluated at all. Producing a
	// decision from a partially understood record is exactly the failure mode
	// this system must not have.
	if !raw.Parsed {
		issues := raw.Issues
		if len(issues) == 0 {
			issues = []string{"the source record could not be parsed"}
		}
		return programOutcome{},
			fmt.Errorf("%s: fetch %s: %w: %v", src.Name(), ref.ID, source.ErrParse, issues)
	}

	program := normalize.Program(raw, s.normalize)
	program.Listing = listingSignalFrom(ref)
	fetchedAt := s.cfg.Now().UTC()
	program.DetailsFetchedAt = &fetchedAt

	// First-observation time is carried forward so that program age does not
	// reset on every scan.
	if hadPrev && !prev.FirstSeenAt.IsZero() {
		program.FirstSeenAt = prev.FirstSeenAt
	}

	d := s.detector.Compare(prev, program)
	decision := s.policy.Evaluate(program)
	fresh := s.computeFreshness(prev, program, d, hadPrev)
	triageScore := s.scorer.Score(program, decision, fresh, d.Changes)

	prior := alerts.PriorDecision{Known: hadPrev}
	if hadPrev {
		// The prior verdict is recomputed from the stored record rather than
		// saved. That is deterministic, keeps the state file small, and means
		// the comparison always reflects the profile in force now rather than
		// the one in force when the record was first judged.
		prior.Eligible = s.policy.Evaluate(prev).Eligible
	}

	return programOutcome{
		Evaluated: Evaluated{
			Program:  program,
			Diff:     d,
			Decision: decision,
			Triage:   triageScore,
			Fresh:    fresh,
			Prior:    prior,
		},
		Freshness:     fresh,
		DetailFetched: true,
	}, nil
}

// needsDetail decides whether the expensive detail read is warranted.
func (s *Scanner) needsDetail(ref domain.ProgramRef, prev domain.Program, hadPrev bool) bool {
	if !hadPrev {
		// A newly discovered program has no record at all, so its access gates
		// are unknown and it cannot be judged.
		return true
	}
	if prev.DetailsFetchedAt == nil {
		// The record was never completed, so it cannot be trusted yet.
		return true
	}
	if s.cfg.Profile.FetchDetailsOnListingChange() && prev.ListingChangedSince(ref) {
		// The listing reports something different. Whether that touches scope
		// or requirements is precisely what the detail page is for.
		return true
	}
	if prev.ParseConfidence == domain.ConfidenceLow {
		// A previous read was incomplete. Retrying on the next sweep is how a
		// transient parsing failure clears without operator involvement.
		return true
	}
	// A periodic refresh keeps access gates from going stale and bounds the cost
	// of any change the listing does not expose at all.
	if interval := s.cfg.Profile.DetailsRefreshInterval(); interval > 0 {
		if s.cfg.Now().Sub(prev.DetailsFetchedAt.UTC()) >= interval {
			return true
		}
	}
	return false
}

// evaluateListingOnly handles a program whose detail page was not read.
//
// The stored record is preserved rather than replaced. The listing is strictly
// poorer than the detail page, so overwriting a complete record with a summary
// would discard the access gates policy depends on. Only freshness is refreshed,
// and no change is claimed, because none was observed.
func (s *Scanner) evaluateListingOnly(ref domain.ProgramRef, prev domain.Program, hadPrev bool) (Evaluated, error) {
	if !hadPrev {
		// Nothing is known and nothing was fetched. Storing a shell record
		// would create a program that can never be judged, so it is skipped.
		return Evaluated{}, errNotEvaluated
	}

	program := prev
	program.LastSeenAt = s.cfg.Now().UTC()
	program.Listing = listingSignalFrom(ref)

	d := domain.Diff{
		ProgramID:          program.ID,
		PreviousLastSeenAt: prev.LastSeenAt,
		FirstSeenAt:        prev.FirstSeenAt,
	}

	// A moving submission count is a genuine observation about competition, and
	// it is recorded here so that it appears in history. It is deliberately not
	// a detail-fetch trigger: the count rises on active programs continuously.
	if ref.Listing.SubmissionsChanged(prev.Listing.AsListing()) {
		d.Changes = append(d.Changes, domain.Change{
			Kind:     domain.ChangeSubmissionsChanged,
			Severity: domain.SeverityLow,
			Field:    "submissions",
			Before:   prev.Listing.SubmissionSummary(),
			After:    ref.Listing.SubmissionSummary(),
			Detail:   "the platform's reported submission count moved",
		})
		d.Changes = domain.SortChanges(d.Changes)
	}

	decision := s.policy.Evaluate(program)

	// Scope and requirement change ages are unavailable when the detail page was
	// not read. Reporting zero would assert that the scope changed at the last
	// observation, which is not something this scan observed.
	fresh := domain.Freshness{}
	age, basis := program.Age(s.cfg.Now())
	fresh.ProgramAge = age
	fresh.ProgramAgeBasis = basis
	if !program.FirstSeenAt.IsZero() {
		fresh.FirstSeenAge = s.cfg.Now().Sub(program.FirstSeenAt)
	}
	if program.SourceUpdatedAt != nil {
		fresh.SourceUpdateAge = s.cfg.Now().Sub(*program.SourceUpdatedAt)
	}

	triageScore := s.scorer.Score(program, decision, fresh, d.Changes)

	return Evaluated{
		Program:  program,
		Diff:     d,
		Decision: decision,
		Triage:   triageScore,
		Fresh:    fresh,
		Prior:    alerts.PriorDecision{Known: true, Eligible: decision.Eligible},
	}, nil
}

// listingSignalFrom projects a reference's listing observation into the storable
// signal form.
func listingSignalFrom(ref domain.ProgramRef) domain.ListingSignal {
	s := domain.ListingSignal{
		UpdatedAt:            ref.Listing.UpdatedAt,
		Status:               ref.Listing.Status,
		State:                ref.Listing.State,
		RewardRaw:            ref.Listing.RewardRaw,
		RewardsPaidRaw:       ref.Listing.RewardsPaidRaw,
		ActivityStatus:       ref.Listing.ActivityStatus,
		Unending:             ref.Listing.Unending,
		Categories:           ref.Listing.Categories,
		ProjectTypes:         ref.Listing.ProjectTypes,
		Technologies:         ref.Listing.Technologies,
		SubmissionCountKnown: ref.Listing.SubmittedReportsKnown,
	}
	if ref.Listing.SubmittedReportsKnown && ref.Listing.SubmittedReports != nil {
		s.SubmissionCount = *ref.Listing.SubmittedReports
	}
	return s
}

// errNotEvaluated marks a program that produced no evaluation this scan.
//
// It is an internal signal rather than a failure: a program that was discovered
// but not read is neither an error nor an alert, and reporting it as either
// would make every listing-only run look broken.
var errNotEvaluated = errors.New("program was not evaluated this scan")

// computeFreshness derives the independent age signals.
func (s *Scanner) computeFreshness(prev, cur domain.Program, d domain.Diff, hadPrev bool) domain.Freshness {
	now := s.cfg.Now()
	f := domain.Freshness{}

	age, basis := cur.Age(now)
	f.ProgramAge = age
	f.ProgramAgeBasis = basis

	if !cur.FirstSeenAt.IsZero() {
		f.FirstSeenAge = now.Sub(cur.FirstSeenAt)
	}
	if cur.SourceUpdatedAt != nil {
		f.SourceUpdateAge = now.Sub(*cur.SourceUpdatedAt)
	}

	// Scope and requirement change ages come from when this system first saw the
	// current fingerprint, which is the only trustworthy signal on a platform
	// whose own update marker has day resolution.
	if hadPrev && prev.ScopeFingerprint != cur.ScopeFingerprint {
		f.ScopeChangeAge = now.Sub(prev.LastSeenAt)
	}
	if hadPrev && prev.RequirementFingerprint != cur.RequirementFingerprint {
		f.RequirementChangeAge = now.Sub(prev.LastSeenAt)
	}
	return f
}

// buildAlerts selects and renders alerts, returning generated and suppressed
// counts.
func (s *Scanner) buildAlerts(evaluated []Evaluated) ([]domain.Alert, int) {
	var (
		out        []domain.Alert
		suppressed int
	)

	for _, e := range evaluated {
		cand := alerts.Candidate{
			Program:  e.Program,
			Diff:     e.Diff,
			Decision: e.Decision,
			Triage:   e.Triage,
			Fresh:    e.Fresh,
			Prior:    e.Prior,
		}
		a := s.generator.Decide(cand)
		if a == nil {
			if shouldHaveAlerted(e) {
				suppressed++
			}
			continue
		}
		a.ScanID = s.cfg.Now().UTC().Format("20060102T150405Z")
		out = append(out, *a)
	}

	capped, dropped := s.generator.CapAlerts(out)
	return capped, suppressed + dropped
}

// shouldHaveAlerted reports whether a candidate met the substantive criteria but
// was withheld, so the summary can distinguish "nothing happened" from "things
// happened but were filtered".
func shouldHaveAlerted(e Evaluated) bool {
	if !e.Decision.Eligible {
		return false
	}
	if e.Diff.IsNew {
		return true
	}
	if e.Prior.Known && !e.Prior.Eligible {
		return true
	}
	return e.Diff.Material()
}

// persist writes the scan's state.
func (s *Scanner) persist(ctx context.Context, snap *state.Snapshot, evaluated []Evaluated, metrics obs.ScanMetrics) error {
	for _, e := range evaluated {
		snap.Programs[e.Program.ID] = e.Program

		// History is recorded only for material change, so that a steady-state
		// scan does not grow the repository on every run.
		if !e.Diff.IsNew && e.Diff.Material() {
			entry := state.HistoryEntry{
				ScanID:     metrics.ScanID,
				At:         s.cfg.Now().UTC(),
				Changes:    e.Diff.Changes,
				Eligible:   e.Decision.Eligible,
				Reasons:    e.Decision.Reasons,
				Kinds:      e.Diff.Changes.Kinds(),
				ScopePrint: e.Program.ScopeFingerprint,
				ReqPrint:   e.Program.RequirementFingerprint,
				MetaPrint:  e.Program.MetadataFingerprint,
			}
			if err := s.cfg.Store.AppendHistory(ctx, e.Program.ID, entry); err != nil {
				return err
			}
		}
	}

	snap.LastScanID = metrics.ScanID
	snap.LastScanAt = s.cfg.Now().UTC()
	return s.cfg.Store.Save(ctx, snap)
}

// deliver sends alerts, honouring dry-run mode and per-alert idempotency.
func (s *Scanner) deliver(ctx context.Context, generated []domain.Alert) (sent, failed, skipped int) {
	if len(generated) == 0 {
		return 0, 0, 0
	}

	dispatcher := notify.NewDispatcher(notify.DispatcherConfig{
		Notifier: s.cfg.Notifier,
		IsDelivered: func(fp string) bool {
			rec, err := s.cfg.Store.AlertRecordFor(ctx, fp)
			if err != nil {
				return false
			}
			return rec.Delivered
		},
		RecordAttempt: func(rec domain.AlertRecord) error {
			return s.cfg.Store.RecordAlertAttempt(ctx, rec)
		},
		RecordDelivered: func(fp string, at time.Time) error {
			return s.cfg.Store.MarkAlertDelivered(ctx, fp, at)
		},
		Now: s.cfg.Now,
	})

	// A dry run still records each alert, but leaves it undelivered.
	//
	// That is what makes a dry run useful: `hunter alerts` shows exactly what
	// would have been sent, and a later live run delivers the very same alerts
	// because their fingerprints are unchanged and their records are still
	// pending. Skipping the record instead would make a dry run invisible and
	// force a second scan to rediscover the same conditions.
	if s.cfg.DryRun || !dispatcher.Status().Notified {
		reason := dispatchReason(s, dispatcher)
		s.cfg.Logger.Info("delivery skipped", "phase", obs.PhaseNotify,
			"reason", reason, "alerts", len(generated))
		for _, a := range generated {
			rec := domain.AlertRecord{
				Fingerprint:   a.Fingerprint,
				Kind:          a.Kind,
				ProgramID:     a.ProgramID,
				ScanID:        a.ScanID,
				CreatedAt:     a.DetectedAt,
				Subject:       a.Subject,
				Body:          a.Body,
				LastAttemptAt: s.cfg.Now().UTC(),
			}
			if err := s.cfg.Store.RecordAlertAttempt(ctx, rec); err != nil {
				s.cfg.Logger.Warn("could not record alert", "phase", obs.PhaseNotify, "error", err.Error())
			}
		}
		return 0, 0, len(generated)
	}

	res, err := dispatcher.Dispatch(ctx, generated)
	if err != nil && s.cfg.Logger != nil {
		for _, e := range res.Errors {
			s.cfg.Logger.Warn("delivery failed", "phase", obs.PhaseNotify, "error", e.Error())
		}
	}
	return res.Delivered, res.Failed, res.Skipped
}

func dispatchReason(s *Scanner, d *notify.Dispatcher) string {
	if s.cfg.DryRun {
		return "dry run"
	}
	if d.Status().Reason != "" {
		return d.Status().Reason
	}
	return "notifier is not configured"
}

// pendingAlerts returns previously generated alerts that were never delivered.
//
// A scan only *generates* alerts for new conditions, so an alert that was created
// by a dry run, or whose delivery failed, would otherwise never be retried: the
// condition that produced it is no longer new. Reconstructing them from their
// records closes that gap, and the dispatcher skips anything already delivered.
func (s *Scanner) pendingAlerts(ctx context.Context) []domain.Alert {
	records, err := s.cfg.Store.ListAlerts(ctx, 0)
	if err != nil {
		s.cfg.Logger.Warn("could not read alert records", "phase", obs.PhaseNotify, "error", err.Error())
		return nil
	}

	out := make([]domain.Alert, 0, len(records))
	for _, rec := range records {
		if rec.Delivered || rec.Subject == "" {
			continue
		}
		out = append(out, domain.Alert{
			Fingerprint: rec.Fingerprint,
			Kind:        rec.Kind,
			ProgramID:   rec.ProgramID,
			ScanID:      rec.ScanID,
			Subject:     rec.Subject,
			Body:        rec.Body,
			DetectedAt:  rec.CreatedAt,
		})
	}
	return out
}

// mergeAlerts combines newly generated alerts with previously pending ones.
//
// New alerts come first so that a genuine opportunity is never delayed behind a
// backlog of retries. Duplicates by fingerprint are dropped in favour of the
// freshly rendered version, which carries the current decision and scoring.
func mergeAlerts(fresh, pending []domain.Alert) []domain.Alert {
	seen := make(map[string]struct{}, len(fresh)+len(pending))
	out := make([]domain.Alert, 0, len(fresh)+len(pending))

	for _, a := range fresh {
		if _, dup := seen[a.Fingerprint]; dup {
			continue
		}
		seen[a.Fingerprint] = struct{}{}
		out = append(out, a)
	}
	for _, a := range pending {
		if _, dup := seen[a.Fingerprint]; dup {
			continue
		}
		seen[a.Fingerprint] = struct{}{}
		out = append(out, a)
	}
	return out
}
