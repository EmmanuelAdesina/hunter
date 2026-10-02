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
	"errors"
	"fmt"
	"io/fs"
	"time"

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
