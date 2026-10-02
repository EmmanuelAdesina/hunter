package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/policy"
	"github.com/eadeshina/hunter/internal/scoring"
	"github.com/eadeshina/hunter/internal/state"
)

// Query answers questions about stored state.
//
// It reuses the same policy engine and scorer that a scan uses, so a decision
// shown by `explain` is the decision a scan would reach. Eligibility is
// recomputed rather than read from storage, which means a profile edit takes
// effect immediately instead of only after the next scan.
type Query struct {
	profile *config.Profile
	store   state.StateStore
	policy  *policy.Engine
	scorer  *scoring.Scorer
	now     func() time.Time
}

// NewQuery builds a query surface over a state store.
func NewQuery(profile *config.Profile, store state.StateStore, now func() time.Time) *Query {
	if now == nil {
		now = time.Now
	}
	return &Query{
		profile: profile,
		store:   store,
		policy:  policy.New(profile, now),
		scorer:  scoring.New(profile),
		now:     now,
	}
}

// ProgramRequest describes a listing query.
type ProgramRequest struct {
	// Eligible keeps only programs the profile accepts.
	Eligible bool
	// New keeps only programs first seen in the most recent scan.
	New bool
	// Changed keeps only programs with a material change in the most recent
	// scan.
	Changed bool
	// Source filters by source name.
	Source string
	// Limit caps the result count. Zero means unlimited.
	Limit int
}

// Programs returns evaluated programs matching the request.
func (q *Query) Programs(ctx context.Context, req ProgramRequest) ([]Evaluated, error) {
	snap, err := q.store.Load(ctx)
	if err != nil {
		return nil, err
	}

	// Material-change detection is per program, so it is resolved once here
	// rather than recomputed for every row.
	changedSet := map[string]bool{}
	if req.Changed {
		for id := range snap.Programs {
			changed, err := q.changedInScan(ctx, snap, id)
			if err != nil {
				return nil, err
			}
			if changed {
				changedSet[id] = true
			}
		}
	}

	out := make([]Evaluated, 0, len(snap.Programs))
	for id, p := range snap.Programs {
		if req.Source != "" && p.Source != req.Source {
			continue
		}
		if req.Eligible && !q.policy.Evaluate(p).Eligible {
			continue
		}
		if req.New && !firstSeenInScan(snap, p) {
			continue
		}
		if req.Changed && !changedSet[id] {
			continue
		}
		ev := q.evaluateStored(p, snap)
		out = append(out, ev)
	}

	sortEvaluated(out)
	if req.Limit > 0 && len(out) > req.Limit {
		out = out[:req.Limit]
	}
	return out, nil
}

// evaluateStored builds a row from a stored record without performing a diff
// against anything, since no previous observation exists at query time.
func (q *Query) evaluateStored(p domain.Program, snap *state.Snapshot) Evaluated {
	decision := q.policy.Evaluate(p)
	fresh := FreshnessFor(p, snap, q.now())

	d := domain.Diff{
		ProgramID:          p.ID,
		FirstSeenAt:        p.FirstSeenAt,
		PreviousLastSeenAt: p.LastSeenAt,
	}
	if firstSeenInScan(snap, p) {
		d.IsNew = true
		d.Changes = domain.ChangeSet{{
			Kind:     domain.ChangeNewProgram,
			Severity: domain.SeverityHigh,
			After:    p.Name,
		}}
	}

	tri := q.scorer.Score(p, decision, fresh, d.Changes)
	return Evaluated{Program: p, Diff: d, Decision: decision, Triage: tri, Fresh: fresh}
}

// changedInScan reports whether a program has a material change recorded for
// the most recent scan.
//
// Change history is consulted rather than a flag on the program, because that
// keeps the program record small and the answer exact: history holds the scan
// each change was observed in.
func (q *Query) changedInScan(ctx context.Context, snap *state.Snapshot, programID string) (bool, error) {
	entries, err := q.store.HistoryFor(ctx, programID)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	last := entries[len(entries)-1]
	return snap.LastScanID != "" && last.ScanID == snap.LastScanID, nil
}

// firstSeenInScan reports whether a program was first observed in the most
// recent scan.
//
// The comparison uses a window rather than an exact timestamp match because a
// program's first-seen time and the scan's completion time differ by the
// duration of the scan itself.
func firstSeenInScan(snap *state.Snapshot, p domain.Program) bool {
	if snap.LastScanID == "" || p.FirstSeenAt.IsZero() || snap.LastScanAt.IsZero() {
		return false
	}
	return snap.LastScanAt.Sub(p.FirstSeenAt) < time.Hour
}

// FreshnessFor derives the age signals for a stored record.
//
// At query time there is no previous observation to compare against, so the
// scope and requirement change ages are unavailable rather than zero. Reporting
// zero would imply the scope changed at the last observation, which is a claim
// that cannot be supported after the fact.
func FreshnessFor(p domain.Program, snap *state.Snapshot, now time.Time) domain.Freshness {
	f := domain.Freshness{}
	age, basis := p.Age(now)
	f.ProgramAge = age
	f.ProgramAgeBasis = basis
	if !p.FirstSeenAt.IsZero() {
		f.FirstSeenAge = now.Sub(p.FirstSeenAt)
	}
	if p.SourceUpdatedAt != nil {
		f.SourceUpdateAge = now.Sub(*p.SourceUpdatedAt)
	}
	return f
}

// Explain returns the full decision for one program.
func (q *Query) Explain(ctx context.Context, query string) (Evaluated, bool, error) {
	snap, err := q.store.Load(ctx)
	if err != nil {
		return Evaluated{}, false, err
	}
	id, ok := ResolveID(snap, query)
	if !ok {
		return Evaluated{}, false, fmt.Errorf("no program matching %q", query)
	}
	p, ok := snap.Program(id)
	if !ok {
		return Evaluated{}, false, fmt.Errorf("no program matching %q", query)
	}
	return q.evaluateStored(p, snap), true, nil
}

// ResolveID maps a user-supplied identifier onto a stored program.
//
// A bare slug is accepted because that is what a human reads off a page. An
// ambiguous slug is reported rather than guessed at.
func ResolveID(snap *state.Snapshot, query string) (string, bool) {
	q := strings.TrimSpace(query)
	if q == "" {
		return "", false
	}
	if _, ok := snap.Program(q); ok {
		return q, true
	}
	matches := make([]string, 0, 4)
	for id, p := range snap.Programs {
		if p.Slug == q || strings.HasSuffix(id, ":"+q) || strings.EqualFold(p.Name, q) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	sort.Strings(matches)
	return "", false
}

// History returns a program's recorded changes.
func (q *Query) History(ctx context.Context, query string) (string, []state.HistoryEntry, error) {
	snap, err := q.store.Load(ctx)
	if err != nil {
		return "", nil, err
	}
	id, ok := ResolveID(snap, query)
	if !ok {
		return "", nil, fmt.Errorf("no program matching %q", query)
	}
	entries, err := q.store.HistoryFor(ctx, id)
	if err != nil {
		return "", nil, err
	}
	return id, entries, nil
}

// Alerts returns recorded alert deliveries.
func (q *Query) Alerts(ctx context.Context, undelivered bool, limit int) ([]domain.AlertRecord, error) {
	records, err := q.store.ListAlerts(ctx, 0)
	if err != nil {
		return nil, err
	}
	if undelivered {
		filtered := make([]domain.AlertRecord, 0, len(records))
		for _, r := range records {
			if !r.Delivered {
				filtered = append(filtered, r)
			}
		}
		records = filtered
	}
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// Snapshot returns the raw stored snapshot, for diagnostics.
func (q *Query) Snapshot(ctx context.Context) (*state.Snapshot, error) { return q.store.Load(ctx) }

// Profile returns the profile in use.
func (q *Query) Profile() *config.Profile { return q.profile }

// sortEvaluated orders rows by attention priority, breaking ties on identifier
// so the ordering is total and reproducible.
func sortEvaluated(in []Evaluated) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Triage.Total != in[j].Triage.Total {
			return in[i].Triage.Total > in[j].Triage.Total
		}
		return in[i].Program.ID < in[j].Program.ID
	})
}
