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
		scorer:  scoring.New(profile, now),
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

	// LaunchWindow filters to programs the source reports as launched within
	// this duration.
	//
	// Zero means no recency filter, so a plain listing still shows everything
	// the monitor knows about. The recency filter is opt-in because applying it
	// by default would silently hide the whole catalogue and make the base
	// listing indistinguishable from "nothing is happening".
	LaunchWindow time.Duration
}

// WindowsRequest describes a query over recorded opportunity windows.
type WindowsRequest struct {
	// OpenOnly excludes windows whose evidence is stale or whose submission
	// count has reached the configured crowding threshold.
	OpenOnly bool

	// Program filters to one program ID, slug, or unambiguous name.
	Program string

	// Limit caps the result count. Zero means unlimited.
	Limit int
}

// WindowView pairs a stored opportunity window with its status under the
// current profile. Status is derived at query time, never persisted as a
// lifecycle state that could drift from the evidence.
type WindowView struct {
	Window domain.OpportunityWindow `json:"window"`
	Status domain.WindowStatus      `json:"status"`
}

// ReplayEvent combines history and opportunity-window records from one recorded
// observation. It contains no re-evaluated eligibility or alert decision.
type ReplayEvent struct {
	Kind       string                    `json:"kind"`
	ScanID     string                    `json:"scan_id,omitempty"`
	RecordedAt *time.Time                `json:"recorded_at,omitempty"`
	Eligible   *bool                     `json:"eligible,omitempty"`
	Reasons    []string                  `json:"reasons,omitempty"`
	Changes    domain.ChangeSet          `json:"changes,omitempty"`
	Windows    []domain.OpportunityWindow `json:"windows,omitempty"`
}

// ReplayTimeline is the recorded evidence for one program, ordered by the
// earliest available observation bound. Intervals remain intervals; replay does
// not invent an exact change time or re-run old decisions.
type ReplayTimeline struct {
	ProgramID string        `json:"program_id"`
	Count     int           `json:"count"`
	Total     int           `json:"total"`
	Events    []ReplayEvent `json:"events"`
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
		if window := q.launchWindow(req); window > 0 && !withinLaunchWindow(p, q.now(), window) {
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

	tri := q.scorer.ScoreWithWindows(p, decision, fresh, d.Changes, snap.WindowsFor(p.ID))
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

// firstSeenInScan reports whether a program was first observed by the most
// recent scan.
//
// The test is whether the observation is newer than the previous scan's
// completion. A sliding window was used before, which made every program look
// new for the first hour after any cold start, because they had all been
// observed within the window. That reported a baseline import as a wave of new
// opportunities, which is precisely the confusion this filter has to avoid.
func firstSeenInScan(snap *state.Snapshot, p domain.Program) bool {
	if p.FirstSeenAt.IsZero() {
		return false
	}
	if snap.LastScanAt.IsZero() {
		// No scan has been recorded yet, so the only observation is this one.
		return true
	}
	return p.FirstSeenAt.After(snap.LastScanAt.Add(-scanOverlapTolerance))
}

// scanOverlapTolerance allows a scan to attribute its own observations to
// itself.
//
// A program discovered partway through a scan has a first-seen time before the
// scan finishes, so a strict comparison would drop it from its own scan's
// results. The tolerance is small relative to the interval and exists only to
// absorb that ordering.
const scanOverlapTolerance = 90 * time.Second

// withinLaunchWindow reports whether a program's source-reported launch date is
// recent enough to count as newly launched.
func withinLaunchWindow(p domain.Program, now time.Time, window time.Duration) bool {
	if !p.StartedAtIsKnown() {
		return false
	}
	age := now.Sub(*p.StartedAt)
	return age >= 0 && age <= window
}

// FreshnessFor derives the age signals for a stored record.
//
// At query time there is no previous observation to compare against, so nothing
// is recomputed: the change intervals stored on the program are read back as
// they were. That is the entire reason they are stored rather than derived.
// A query must be able to answer "how long ago did the scope change?" long after
// the scan that detected it, which a per-scan derivation cannot do.
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
	f.ScopeChange = p.ScopeChanged
	f.RequirementChange = p.RequirementsChanged
	f.MetadataChange = p.MetadataChanged
	f.LifecycleChange = p.LifecycleChanged
	return f
}

// launchWindow resolves the requested recency filter.
//
// Zero means the caller did not ask for one. It deliberately does not fall back
// to the profile window: the profile window governs alerting, while this filter
// governs a query, and conflating them would make the default listing empty.
func (q *Query) launchWindow(req ProgramRequest) time.Duration {
	return req.LaunchWindow
}

// Windows returns recorded opportunity windows, with status derived from the
// current time and profile thresholds.
func (q *Query) Windows(ctx context.Context, req WindowsRequest) ([]WindowView, error) {
	snap, err := q.store.Load(ctx)
	if err != nil {
		return nil, err
	}

	programID := ""
	if strings.TrimSpace(req.Program) != "" {
		var ok bool
		programID, ok = ResolveID(snap, req.Program)
		if !ok {
			return nil, fmt.Errorf("no program matching %q", req.Program)
		}
	}

	now := q.now()
	opts := domain.OpportunityWindowOptions{
		Now:                      now,
		MaxAge:                   q.profile.ChangeWindowMaxAge(),
		MaxPostChangeSubmissions: q.profile.MaxPostChangeSubmissions(),
	}
	out := make([]WindowView, 0, len(snap.Windows))
	for _, window := range snap.Windows {
		if programID != "" && window.ProgramID != programID {
			continue
		}
		status := window.Status(now, opts)
		if req.OpenOnly && status != domain.WindowOpen {
			continue
		}
		out = append(out, WindowView{Window: window, Status: status})
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Window.Observed.NotAfter, out[j].Window.Observed.NotAfter
		if a.IsZero() != b.IsZero() {
			return !a.IsZero()
		}
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i].Window.ID < out[j].Window.ID
	})
	if req.Limit > 0 && len(out) > req.Limit {
		out = out[:req.Limit]
	}
	return out, nil
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

// Replay reconstructs a read-only timeline from saved history and opportunity
// windows. It does not re-run policy, scoring, alert generation, or source reads.
func (q *Query) Replay(ctx context.Context, query string, limit int) (ReplayTimeline, error) {
	snap, err := q.store.Load(ctx)
	if err != nil {
		return ReplayTimeline{}, err
	}
	id, ok := ResolveID(snap, query)
	if !ok {
		return ReplayTimeline{}, fmt.Errorf("no program matching %q", query)
	}

	entries, err := q.store.HistoryFor(ctx, id)
	if err != nil {
		return ReplayTimeline{}, err
	}
	events := make([]ReplayEvent, 0, len(entries)+len(snap.Windows))
	byScan := make(map[string]int, len(entries))
	for _, entry := range entries {
		recordedAt := entry.At
		eligible := entry.Eligible
		event := ReplayEvent{
			Kind:       "change_history",
			ScanID:     entry.ScanID,
			RecordedAt: &recordedAt,
			Eligible:   &eligible,
			Reasons:    entry.Reasons,
			Changes:    entry.Changes,
		}
		byScan[entry.ScanID] = len(events)
		events = append(events, event)
	}

	for _, window := range snap.WindowsFor(id) {
		if index, found := byScan[window.OpenedScanID]; found && window.OpenedScanID != "" {
			events[index].Windows = append(events[index].Windows, window)
			events[index].Kind = replayEventKind(events[index])
			continue
		}
		events = append(events, ReplayEvent{
			Kind:    "opportunity_window",
			ScanID:  window.OpenedScanID,
			Windows: []domain.OpportunityWindow{window},
		})
	}

	for i := range events {
		events[i].Kind = replayEventKind(events[i])
		sort.SliceStable(events[i].Windows, func(a, b int) bool {
			left, leftKnown := events[i].Windows[a].Observed.NotBefore, events[i].Windows[a].Observed.Known()
			right, rightKnown := events[i].Windows[b].Observed.NotBefore, events[i].Windows[b].Observed.Known()
			if leftKnown != rightKnown {
				return leftKnown
			}
			if leftKnown && !left.Equal(right) {
				return left.Before(right)
			}
			return events[i].Windows[a].ID < events[i].Windows[b].ID
		})
	}
	sort.SliceStable(events, func(i, j int) bool {
		left, leftKnown := replayOrderTime(events[i])
		right, rightKnown := replayOrderTime(events[j])
		if leftKnown != rightKnown {
			return leftKnown
		}
		if leftKnown && !left.Equal(right) {
			return left.Before(right)
		}
		if events[i].ScanID != events[j].ScanID {
			return events[i].ScanID < events[j].ScanID
		}
		return replayWindowID(events[i]) < replayWindowID(events[j])
	})

	total := len(events)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return ReplayTimeline{
		ProgramID: id,
		Count:     len(events),
		Total:     total,
		Events:    events,
	}, nil
}

func replayEventKind(event ReplayEvent) string {
	hasHistory := event.Eligible != nil || event.RecordedAt != nil
	if len(event.Windows) > 0 && hasHistory {
		return "change_and_window"
	}
	if len(event.Windows) > 0 {
		return "opportunity_window"
	}
	return "change_history"
}

func replayOrderTime(event ReplayEvent) (time.Time, bool) {
	var earliest time.Time
	for _, window := range event.Windows {
		if !window.Observed.Known() {
			continue
		}
		if earliest.IsZero() || window.Observed.NotBefore.Before(earliest) {
			earliest = window.Observed.NotBefore
		}
	}
	if !earliest.IsZero() {
		return earliest, true
	}
	if event.RecordedAt != nil {
		return *event.RecordedAt, true
	}
	return time.Time{}, false
}

func replayWindowID(event ReplayEvent) string {
	if len(event.Windows) == 0 {
		return ""
	}
	return event.Windows[0].ID
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

// Now returns the clock the query evaluates against.
func (q *Query) Now() time.Time { return q.now() }

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
