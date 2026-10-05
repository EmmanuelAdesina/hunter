// Package state persists what the system has seen so that change detection and
// alert deduplication work across runs.
//
// The interface is deliberately narrow so that a database can replace the file
// implementation without any business logic changing. Nothing in this package
// knows about scanning, policy, or alerting; it stores and retrieves records.
//
// Durability rules that shape the implementation:
//   - Writes are atomic. A scan interrupted mid-write must not leave state that
//     the next run cannot parse.
//   - Serialization is deterministic. State lives in version control, so a run
//     that changed nothing must produce a byte-identical file.
//   - Reads are tolerant, writes are strict. A corrupt file is reported rather
//     than silently replaced, because discarding history would make every
//     program look new and trigger a flood of alerts.
package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/canon"
	"github.com/eadeshina/hunter/internal/domain"
)

// ErrCorrupt reports that stored state could not be parsed.
//
// It is surfaced rather than handled internally so that a human decides whether
// to restore from version control or to accept the loss.
var ErrCorrupt = errors.New("state: stored data is corrupt")

// ErrNotFound reports that a requested record does not exist.
var ErrNotFound = errors.New("state: record not found")

// Snapshot is the complete persisted view of the world at a point in time.
type Snapshot struct {
	// Version identifies the on-disk layout so that future migrations can be
	// detected rather than guessed at.
	Version int `json:"version"`

	// LastScanID identifies the scan that produced this snapshot.
	LastScanID string `json:"last_scan_id"`

	// LastScanAt is when that scan completed.
	LastScanAt time.Time `json:"last_scan_at"`

	// Programs holds one record per known program, keyed by program ID.
	Programs map[string]domain.Program `json:"programs"`

	// Alerts holds delivery records keyed by alert fingerprint, which is what
	// makes redelivery after a workflow retry idempotent.
	Alerts map[string]domain.AlertRecord `json:"alerts"`

	// History holds per-program change history, oldest first, keyed by program
	// ID.
	History map[string][]HistoryEntry `json:"history,omitempty"`

	// Windows holds open and expired opportunity windows, keyed by window ID.
	//
	// Windows live in this snapshot rather than in a file of their own so that a
	// program's record, its history, and the opportunity it created are written in
	// one atomic transition. A separate file would introduce a consistency
	// boundary this design exists to remove: the repository could end up asserting
	// a program changed while the opportunity it produced went missing, or the
	// reverse. The state file is the long-term evidence store, and evidence that
	// can disagree with itself is not evidence.
	Windows map[string]domain.OpportunityWindow `json:"windows,omitempty"`
}

// HistoryEntry records one material change to a program.
//
// Storing these separately from the current state is what makes "when did this
// program gain an API?" answerable after the fact, and what lets a future
// profile be evaluated retrospectively.
type HistoryEntry struct {
	ScanID     string           `json:"scan_id"`
	At         time.Time        `json:"at"`
	Changes    domain.ChangeSet `json:"changes,omitempty"`
	Eligible   bool             `json:"eligible"`
	Reasons    []string         `json:"reasons,omitempty"`
	Kinds      []string         `json:"kinds,omitempty"`
	ScopePrint string           `json:"scope_fingerprint,omitempty"`
	ReqPrint   string           `json:"requirement_fingerprint,omitempty"`
	MetaPrint  string           `json:"metadata_fingerprint,omitempty"`
}

// StateStore is the persistence boundary.
//
// The methods are coarse on purpose: a scan loads once and saves once, rather
// than performing a read-modify-write per program. That keeps the number of
// failure windows small and makes a run's state transition effectively atomic.
type StateStore interface {
	// Load reads the current snapshot.
	//
	// A missing snapshot is not an error: it is the first run. The returned
	// snapshot is empty but usable.
	Load(ctx context.Context) (*Snapshot, error)

	// Save writes the snapshot durably.
	Save(ctx context.Context, s *Snapshot) error

	// AppendHistory records a material change for later inspection.
	AppendHistory(ctx context.Context, programID string, entry HistoryEntry) error

	// HistoryFor returns a program's recorded history, oldest first.
	HistoryFor(ctx context.Context, programID string) ([]HistoryEntry, error)

	// RecordAlertAttempt persists an attempt to deliver an alert.
	//
	// The record is written before delivery is attempted so that a crash
	// between send and record is detectable rather than invisible.
	RecordAlertAttempt(ctx context.Context, rec domain.AlertRecord) error

	// MarkAlertDelivered records successful delivery.
	MarkAlertDelivered(ctx context.Context, fingerprint string, at time.Time) error

	// AlertRecordFor returns the delivery record for a fingerprint.
	AlertRecordFor(ctx context.Context, fingerprint string) (domain.AlertRecord, error)

	// ListAlerts returns every stored alert record, newest first.
	ListAlerts(ctx context.Context, limit int) ([]domain.AlertRecord, error)

	// Describe returns a human-readable description of the backing store, for
	// diagnostics.
	Describe() string
}

// CurrentVersion is the on-disk layout version this build reads and writes.
const CurrentVersion = 1

// NewSnapshot returns an empty, usable snapshot.
func NewSnapshot() *Snapshot {
	return &Snapshot{
		Version:  CurrentVersion,
		Programs: map[string]domain.Program{},
		Alerts:   map[string]domain.AlertRecord{},
		History:  map[string][]HistoryEntry{},
		Windows:  map[string]domain.OpportunityWindow{},
	}
}

// EnsureMaps repairs a snapshot loaded from disk, so that callers never have to
// guard against nil maps.
func (s *Snapshot) EnsureMaps() {
	if s.Programs == nil {
		s.Programs = map[string]domain.Program{}
	}
	if s.Alerts == nil {
		s.Alerts = map[string]domain.AlertRecord{}
	}
	if s.History == nil {
		s.History = map[string][]HistoryEntry{}
	}
	// A snapshot written before windows existed deserializes with a nil map. It is
	// repaired here rather than migrated: an absent key and an empty set mean the
	// same thing, so no version bump is warranted for an additive field.
	if s.Windows == nil {
		s.Windows = map[string]domain.OpportunityWindow{}
	}
}

// Program returns a stored program by ID.
func (s *Snapshot) Program(id string) (domain.Program, bool) {
	p, ok := s.Programs[id]
	return p, ok
}

// AlertDelivered reports whether an alert has already been delivered.
func (s *Snapshot) AlertDelivered(fingerprint string) bool {
	rec, ok := s.Alerts[fingerprint]
	return ok && rec.Delivered
}

// MaxHistoryPerProgram bounds retained history.
//
// Unbounded history would grow without limit in a repository that is committed
// on every run. Older entries are dropped rather than compacted because their
// only consumer is human inspection of recent history.
const MaxHistoryPerProgram = 200

// MaxDeliveredAlerts bounds retained delivery records.
//
// Every record carries a full rendered alert body of a few kilobytes, and the
// whole file is rewritten on every save. Without a bound the file grows for as
// long as the system runs, and both the write cost and the version-control churn
// grow with it.
//
// Undelivered alerts are never pruned: they are the ones still owed to the
// researcher, and discarding them would silently lose an opportunity. Only
// delivered records are eligible for removal.
const MaxDeliveredAlerts = 500

// MaterialDigest is a hash over the parts of a snapshot that affect future
// decisions.
//
// It exists because the snapshot also carries fields that change on every scan -
// last-seen times and scan metadata - which would otherwise make every scheduled
// run produce a commit. Comparing digests instead of files means the repository
// is only written when the system genuinely learned something: a new program, a
// real change, an alert, or a new history entry.
//
// LastSeenAt, LastScanID, and LastScanAt are excluded as per-run metadata. In
// contrast, source launch age, first-seen time, detail-refresh time, observed
// submission counts, change intervals, and the listing signal are included
// because they affect refresh scheduling, trigger gates, or scoring.
func (s *Snapshot) MaterialDigest() string {
	h := sha256.New()

	fmt.Fprintf(h, "hunter/state-material/v1\n")

	programs := make([]string, 0, len(s.Programs))
	for id := range s.Programs {
		programs = append(programs, id)
	}
	sort.Strings(programs)
	for _, id := range programs {
		p := s.Programs[id]
		fmt.Fprintf(h, "program=%s scope=%s req=%s meta=%s listing=%s state=%s name=%q\n",
			id, p.ScopeFingerprint, p.RequirementFingerprint,
			p.MetadataFingerprint, p.Listing.Digest(), p.State, p.Name)
		decisionInputs := struct {
			StartedAt                   *time.Time
			FirstSeenAt                 time.Time
			DetailsFetchedAt            *time.Time
			SubmittedReports            *int
			SubmittedReportsKnown       bool
			ListingSubmissionCount      int
			ListingSubmissionCountKnown bool
			ParseConfidence             domain.Confidence
			ParseIssues                 []string
			SurfaceTags                 domain.Tags
			ScopeChanged                domain.ObservationInterval
			RequirementsChanged         domain.ObservationInterval
			MetadataChanged             domain.ObservationInterval
			LifecycleChanged            domain.ObservationInterval
		}{
			StartedAt:                   p.StartedAt,
			FirstSeenAt:                 p.FirstSeenAt,
			DetailsFetchedAt:            p.DetailsFetchedAt,
			SubmittedReports:            p.SubmittedReports,
			SubmittedReportsKnown:       p.SubmittedReportsKnown,
			ListingSubmissionCount:      p.Listing.SubmissionCount,
			ListingSubmissionCountKnown: p.Listing.SubmissionCountKnown,
			ParseConfidence:             p.ParseConfidence,
			ParseIssues:                 p.ParseIssues,
			SurfaceTags:                 p.SurfaceTags,
			ScopeChanged:                p.ScopeChanged,
			RequirementsChanged:         p.RequirementsChanged,
			MetadataChanged:             p.MetadataChanged,
			LifecycleChanged:            p.LifecycleChanged,
		}
		encodedInputs, err := canon.Marshal(decisionInputs)
		if err != nil {
			fmt.Fprintf(h, "program-inputs-unencodable=%q\n", err)
		} else {
			fmt.Fprintf(h, "program-inputs=%s %s\n", id, encodedInputs)
		}
	}

	alerts := make([]string, 0, len(s.Alerts))
	for fp := range s.Alerts {
		alerts = append(alerts, fp)
	}
	sort.Strings(alerts)
	for _, fp := range alerts {
		rec := s.Alerts[fp]
		fmt.Fprintf(h, "alert=%s delivered=%t kind=%s subject=%q\n",
			fp, rec.Delivered, rec.Kind, rec.Subject)
	}

	history := make([]string, 0, len(s.History))
	for id := range s.History {
		history = append(history, id)
	}
	sort.Strings(history)
	for _, id := range history {
		entries := s.History[id]
		fmt.Fprintf(h, "history=%s entries=%d\n", id, len(entries))
		// The newest entry identifies what was learned; older ones cannot change.
		if n := len(entries); n > 0 {
			last := entries[n-1]
			fmt.Fprintf(h, "  last=%s kinds=%s eligible=%t\n",
				last.ScanID, strings.Join(last.Kinds, ","), last.Eligible)
		}
	}

	windows := make([]string, 0, len(s.Windows))
	for id := range s.Windows {
		windows = append(windows, id)
	}
	sort.Strings(windows)
	for _, id := range windows {
		w := s.Windows[id]
		// Only the fields that can change a decision are hashed. Notified and
		// NotifiedAt are excluded because they change when a mail is sent rather
		// than when anything was learned, and including them would make delivery
		// state look like new evidence.
		fmt.Fprintf(h, "window=%s program=%s not_before=%s not_after=%s deltas=%s baseline=%s current=%s movement=%s\n",
			id, w.ProgramID,
			w.Observed.NotBefore.UTC().Format(time.RFC3339Nano),
			w.Observed.NotAfter.UTC().Format(time.RFC3339Nano),
			w.Deltas.Identity(),
			intPtrString(w.BaselineSubmissions),
			intPtrString(w.CurrentSubmissions),
			intPtrString(w.SubmissionsSinceOpen),
		)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func intPtrString(v *int) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v)
}

// RecordWindow stores a window, keeping the earliest creation evidence.
//
// Re-observing a window that already exists refreshes its competition signals
// but never its observed interval: the interval records when the transition was
// seen, and rewriting it would silently move the origin of the measurement.
func (s *Snapshot) RecordWindow(w domain.OpportunityWindow) {
	if w.ID == "" {
		return
	}
	if s.Windows == nil {
		s.Windows = map[string]domain.OpportunityWindow{}
	}
	existing, known := s.Windows[w.ID]
	if !known {
		s.Windows[w.ID] = w
		return
	}
	existing.Deltas = w.Deltas
	existing.Triggers = w.Triggers
	existing.AssetsAdded = w.AssetsAdded
	existing.CurrentSubmissions = w.CurrentSubmissions
	existing.SubmissionsSinceOpen = w.SubmissionsSinceOpen
	if existing.BaselineSubmissions == nil {
		existing.BaselineSubmissions = w.BaselineSubmissions
	}
	// Notified is sticky: once an alert has been raised for this window, a later
	// scan must not raise a second one.
	if w.Notified {
		existing.Notified = true
		existing.NotifiedAt = w.NotifiedAt
	}
	s.Windows[w.ID] = existing
}

// WindowsFor returns a program's windows, newest first.
func (s *Snapshot) WindowsFor(programID string) []domain.OpportunityWindow {
	out := make([]domain.OpportunityWindow, 0, 4)
	for _, w := range s.Windows {
		if w.ProgramID == programID {
			out = append(out, w)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Observed.NotAfter.Equal(out[j].Observed.NotAfter) {
			return out[i].Observed.NotAfter.After(out[j].Observed.NotAfter)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// MaxWindowsPerProgram bounds retained windows.
//
// Windows are evidence, but unbounded growth would make the state file
// expensive to rewrite on every run and expensive to review. The cap drops the
// oldest windows, which are the ones whose intervals have expired and which
// therefore have the least left to act on.
const MaxWindowsPerProgram = 50

// pruneWindows drops the oldest windows beyond the per-program cap.
func (s *Snapshot) pruneWindows() int {
	if len(s.Windows) == 0 {
		return 0
	}
	counts := map[string]int{}
	for _, w := range s.Windows {
		counts[w.ProgramID]++
	}
	drop := map[string]struct{}{}
	for programID, n := range counts {
		if n <= MaxWindowsPerProgram {
			continue
		}
		ordered := s.WindowsFor(programID)
		for i := MaxWindowsPerProgram; i < len(ordered); i++ {
			drop[ordered[i].ID] = struct{}{}
		}
	}
	for id := range drop {
		delete(s.Windows, id)
	}
	return len(drop)
}

// Delivered records are retained in newest-first order and pruned from the end,
// which is the order they stop being interesting in.
func pruneAlerts(alerts map[string]domain.AlertRecord) int {
	if len(alerts) <= MaxDeliveredAlerts {
		return 0
	}

	delivered := make([]domain.AlertRecord, 0, len(alerts))
	for _, rec := range alerts {
		if rec.Delivered {
			delivered = append(delivered, rec)
		}
	}

	excess := len(delivered) - MaxDeliveredAlerts
	if excess <= 0 {
		return 0
	}

	sort.Slice(delivered, func(i, j int) bool {
		return delivered[i].CreatedAt.After(delivered[j].CreatedAt)
	})
	for _, rec := range delivered[:excess] {
		delete(alerts, rec.Fingerprint)
	}
	return excess
}

// appendHistoryBounded adds an entry, trimming the oldest beyond the cap.
func appendHistoryBounded(entries []HistoryEntry, entry HistoryEntry) []HistoryEntry {
	out := append(entries, entry)
	if len(out) <= MaxHistoryPerProgram {
		return out
	}
	return out[len(out)-MaxHistoryPerProgram:]
}

// classifyLoadError maps a filesystem error onto the package's sentinels.
func classifyLoadError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("load state: %w", err)
}

// RecordAlert stores an alert record in the snapshot.
//
// The snapshot owns the attempt count rather than the caller, because it is the
// only component that can see history across a workflow retry. Recording an alert
// that is already known refreshes its subject and body rather than resetting it,
// so a redelivery always carries the current rendering.
//
// A delivered alert is never reopened by a later scan. Doing so would resend a
// message the researcher already has, which is the one failure mode that would
// make the alert channel unusable.
func (s *Snapshot) RecordAlert(rec domain.AlertRecord) {
	if rec.Fingerprint == "" {
		return
	}
	if s.Alerts == nil {
		s.Alerts = map[string]domain.AlertRecord{}
	}

	existing, known := s.Alerts[rec.Fingerprint]
	if !known {
		rec.Attempts = 1
		s.Alerts[rec.Fingerprint] = rec
		return
	}
	if existing.Delivered {
		return
	}

	rec.Attempts = existing.Attempts + 1
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = existing.CreatedAt
	}
	if existing.CreatedAt.Before(rec.CreatedAt) {
		// The original detection time is what identifies the event, so the
		// earliest of the two is preserved.
		rec.CreatedAt = existing.CreatedAt
	}
	s.Alerts[rec.Fingerprint] = rec
}
