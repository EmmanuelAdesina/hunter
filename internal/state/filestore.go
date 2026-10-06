package state

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/canon"
	"github.com/eadeshina/hunter/internal/domain"
)

// FileStore persists state as JSON under a directory.
//
// The layout is intentionally reviewable and diff-friendly:
//
//	programs.json                 current program records
//	alerts.json                   alert delivery records
//	windows.json                  opportunity scoring windows
//	history/<program>.json        per-program change history
//	material.sha256               material-change marker for scheduled runs
//	.save-transaction.json        recoverable multi-file save journal
//
// The state remains split into focused files, while the hidden transaction
// journal makes each multi-file snapshot recoverable as a unit.
type FileStore struct {
	dir string

	// programsPath and alertsPath are resolved once so that path handling does
	// not drift between methods.
	programsPath string
	windowsPath  string
	alertsPath   string
	historyDir   string
	digestPath   string
	txnPath      string
}

// NewFileStore builds a store rooted at dir.
func NewFileStore(dir string) *FileStore {
	return &FileStore{
		dir:          dir,
		programsPath: filepath.Join(dir, "programs.json"),
		alertsPath:   filepath.Join(dir, "alerts.json"),
		historyDir:   filepath.Join(dir, "history"),
		windowsPath:  filepath.Join(dir, "windows.json"),
		digestPath:   filepath.Join(dir, "material.sha256"),
		txnPath:      filepath.Join(dir, ".save-transaction.json"),
	}
}

// Describe implements StateStore.
func (s *FileStore) Describe() string { return "file:" + s.dir }

// programsFile is the on-disk shape of the program file. The wrapper records
// the version separately from the map so that a future layout change is
// detectable rather than silently misread.
type programsFile struct {
	Version    int                       `json:"version"`
	LastScanID string                    `json:"last_scan_id"`
	LastScanAt time.Time                 `json:"last_scan_at"`
	Programs   map[string]domain.Program `json:"programs"`
}

// alertsFile is the on-disk shape of the alert file.
type alertsFile struct {
	Version int                           `json:"version"`
	Alerts  map[string]domain.AlertRecord `json:"alerts"`
}

// windowsFile is the on-disk shape of the window set.
//
// Windows are written as their own file for reviewability. The save transaction
// journal makes the programs, alerts, windows, and material digest recover as one
// snapshot if the process stops between their individual atomic replacements.
type windowsFile struct {
	Version int                                 `json:"version"`
	Windows map[string]domain.OpportunityWindow `json:"windows"`
}

// saveTransaction is a write-ahead record for the files that make up one
// snapshot. Each individual file is atomically replaced, but the snapshot spans
// several files. Keeping the complete new snapshot in this record means a
// process or host interruption can be completed on the next Load instead of
// exposing a new program baseline without its pending alert.
type saveTransaction struct {
	Version  int          `json:"version"`
	Programs programsFile `json:"programs"`
	Alerts   alertsFile   `json:"alerts"`
	Windows  windowsFile  `json:"windows"`
	Digest   string       `json:"digest"`
}

// Load implements StateStore.
func (s *FileStore) Load(ctx context.Context) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.recoverSaveTransaction(); err != nil {
		return nil, err
	}

	snap := NewSnapshot()

	pf, err := s.readPrograms()
	if err != nil {
		return nil, err
	}
	if pf != nil {
		snap.Version = pf.Version
		snap.LastScanID = pf.LastScanID
		snap.LastScanAt = pf.LastScanAt
		snap.Programs = pf.Programs
	}

	af, err := s.readAlerts()
	if err != nil {
		return nil, err
	}
	if af != nil {
		snap.Alerts = af.Alerts
	}

	wf, err := s.readWindows()
	if err != nil {
		return nil, err
	}
	if wf != nil {
		snap.Windows = wf.Windows
	}

	snap.EnsureMaps()
	if snap.Version == 0 {
		snap.Version = CurrentVersion
	}
	if err := s.validateMaterialDigest(snap); err != nil {
		return nil, err
	}

	// History is loaded lazily by HistoryFor. A scan does not need it, and
	// loading every program's history on every five-minute run would read
	// files it does not use.
	return snap, nil
}

// validateMaterialDigest detects a state-file mixture left by an older
// interrupted save, or an out-of-band edit. Missing digests are accepted for
// backward compatibility with state created before the digest was introduced;
// once present, the digest must describe the complete loaded snapshot.
func (s *FileStore) validateMaterialDigest(snap *Snapshot) error {
	raw, err := os.ReadFile(s.digestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read material digest: %w", err)
	}
	got := strings.TrimSpace(string(raw))
	want := snap.MaterialDigest()
	if got != want {
		return fmt.Errorf("%w: material digest mismatch (stored %q, computed %q); state may be inconsistent",
			ErrCorrupt, got, want)
	}
	return nil
}

func (s *FileStore) readWindows() (*windowsFile, error) {
	raw, err := os.ReadFile(s.windowsPath)
	if err != nil {
		if err2 := classifyLoadError(err); err2 != nil {
			return nil, err2
		}
		return nil, nil
	}
	var wf windowsFile
	if err := json.Unmarshal(raw, &wf); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(s.windowsPath), err)
	}
	if wf.Version > CurrentVersion {
		return nil, fmt.Errorf("%w: %s has version %d, this build understands %d",
			ErrCorrupt, filepath.Base(s.windowsPath), wf.Version, CurrentVersion)
	}
	return &wf, nil
}

func (s *FileStore) readPrograms() (*programsFile, error) {
	raw, err := os.ReadFile(s.programsPath)
	if err != nil {
		if err2 := classifyLoadError(err); err2 != nil {
			return nil, err2
		}
		return nil, nil
	}
	var pf programsFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(s.programsPath), err)
	}
	if pf.Version > CurrentVersion {
		return nil, fmt.Errorf("%w: %s has version %d, this build understands %d",
			ErrCorrupt, filepath.Base(s.programsPath), pf.Version, CurrentVersion)
	}
	pf.Programs = filterUsablePrograms(pf.Programs)
	return &pf, nil
}

func (s *FileStore) readAlerts() (*alertsFile, error) {
	raw, err := os.ReadFile(s.alertsPath)
	if err != nil {
		if err2 := classifyLoadError(err); err2 != nil {
			return nil, err2
		}
		return nil, nil
	}
	var af alertsFile
	if err := json.Unmarshal(raw, &af); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(s.alertsPath), err)
	}
	if af.Alerts == nil {
		af.Alerts = map[string]domain.AlertRecord{}
	}
	return &af, nil
}

// Save implements StateStore.
func (s *FileStore) Save(ctx context.Context, snap *Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("save state: snapshot is nil")
	}
	// Complete an earlier interrupted save before preparing another one. This
	// also prevents a later Save from replacing the recovery record while some of
	// its files are still from the previous snapshot.
	if err := s.recoverSaveTransaction(); err != nil {
		return err
	}
	snap.EnsureMaps()
	// Apply the same normalization Load uses before hashing and writing so the
	// committed digest cannot describe records that Load will later discard.
	snap.Programs = filterUsablePrograms(snap.Programs)

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	// Undelivered alerts are retained unconditionally; only delivered records
	// past the cap are dropped, so an alert still owed to the researcher is
	// never the one discarded.
	pruneAlerts(snap.Alerts)
	snap.pruneWindows()

	txn := saveTransaction{
		Version: CurrentVersion,
		Programs: programsFile{
			Version:    CurrentVersion,
			LastScanID: snap.LastScanID,
			LastScanAt: snap.LastScanAt.UTC(),
			Programs:   snap.Programs,
		},
		Alerts:  alertsFile{Version: CurrentVersion, Alerts: snap.Alerts},
		Windows: windowsFile{Version: CurrentVersion, Windows: snap.Windows},
		Digest:  snap.MaterialDigest(),
	}
	if err := writeCanonicalFile(s.txnPath, txn); err != nil {
		return fmt.Errorf("write state transaction: %w", err)
	}
	return s.applySaveTransaction(txn)
}

// recoverSaveTransaction replays a pending transaction before any snapshot is
// read. The transaction file remains present until every state file and the
// material digest are durable, so replay is safe and idempotent.
func (s *FileStore) recoverSaveTransaction() error {
	raw, err := os.ReadFile(s.txnPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read state transaction: %w", err)
	}

	var txn saveTransaction
	if err := json.Unmarshal(raw, &txn); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Base(s.txnPath), err)
	}
	if txn.Version != CurrentVersion || txn.Programs.Version != CurrentVersion ||
		txn.Alerts.Version != CurrentVersion || txn.Windows.Version != CurrentVersion {
		return fmt.Errorf("%w: unsupported state transaction version %d", ErrCorrupt, txn.Version)
	}
	if txn.Programs.Programs == nil || txn.Alerts.Alerts == nil ||
		txn.Windows.Windows == nil || strings.TrimSpace(txn.Digest) == "" {
		return fmt.Errorf("%w: incomplete state transaction", ErrCorrupt)
	}
	return s.applySaveTransaction(txn)
}

// applySaveTransaction writes the transaction's state files and removes its
// journal only after the material digest has been installed last.
func (s *FileStore) applySaveTransaction(txn saveTransaction) error {
	if err := writeCanonicalFile(s.programsPath, txn.Programs); err != nil {
		return fmt.Errorf("write programs: %w", err)
	}
	if err := writeCanonicalFile(s.alertsPath, txn.Alerts); err != nil {
		return fmt.Errorf("write alerts: %w", err)
	}
	if err := writeCanonicalFile(s.windowsPath, txn.Windows); err != nil {
		return fmt.Errorf("write windows: %w", err)
	}

	// The material digest is written last and is the only file the scheduled
	// workflow compares, so a scan that learned nothing produces no commit.
	if err := writeRawFile(s.digestPath, txn.Digest+"\n"); err != nil {
		return fmt.Errorf("write material digest: %w", err)
	}
	if err := os.Remove(s.txnPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove state transaction: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

// writeRawFile writes plain bytes atomically.
//
// The digest is compared as text by the workflow, so it is not JSON-encoded: a
// quoted, escaped string would still be comparable, but it would read as though
// the file held a JSON document rather than a checksum.
func writeRawFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.WriteString(content); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := replaceFile(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// AppendHistory implements StateStore.
func (s *FileStore) AppendHistory(ctx context.Context, programID string, entry HistoryEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if programID == "" {
		return fmt.Errorf("append history: program id is empty")
	}
	existing, err := s.readHistory(programID)
	if err != nil {
		return err
	}
	updated := appendHistoryBounded(existing, entry)
	return writeCanonicalFile(s.historyPath(programID), updated)
}

// HistoryFor implements StateStore.
func (s *FileStore) HistoryFor(ctx context.Context, programID string) ([]HistoryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.readHistory(programID)
}

func (s *FileStore) readHistory(programID string) ([]HistoryEntry, error) {
	path := s.historyPath(programID)
	raw, err := os.ReadFile(path)
	if err != nil {
		if err2 := classifyLoadError(err); err2 != nil {
			return nil, err2
		}
		return nil, nil
	}
	var entries []HistoryEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%w: history/%s: %v", ErrCorrupt, programID, err)
	}
	return entries, nil
}

// historyPath returns the per-program history path.
//
// The program ID is sanitized because it reaches the filesystem. Slugs are
// already URL-safe, but a future source could supply an ID containing a path
// separator, and that must not be able to escape the state directory.
func (s *FileStore) historyPath(programID string) string {
	return filepath.Join(s.historyDir, sanitizeName(programID)+".json")
}

// RecordAlertAttempt implements StateStore.
//
// The store owns the attempt count. A caller reports that an attempt happened,
// not how many have happened in total, because the store is the only component
// that can see history across a workflow retry.
func (s *FileStore) RecordAlertAttempt(ctx context.Context, rec domain.AlertRecord) error {
	if rec.Fingerprint == "" {
		return fmt.Errorf("record alert attempt: fingerprint is empty")
	}
	snap, err := s.Load(ctx)
	if err != nil {
		return err
	}
	existing, ok := snap.Alerts[rec.Fingerprint]
	if !ok {
		existing = domain.AlertRecord{
			Fingerprint: rec.Fingerprint,
			CreatedAt:   rec.CreatedAt,
		}
	}
	existing.Attempts++
	existing.Kind = rec.Kind
	existing.ProgramID = rec.ProgramID
	existing.ScanID = rec.ScanID
	existing.Subject = rec.Subject
	// The body is refreshed on every attempt so that a redelivery always carries
	// the current rendering rather than a stale one.
	existing.Body = rec.Body
	existing.LastAttemptAt = rec.LastAttemptAt
	existing.LastError = rec.LastError
	if existing.CreatedAt.IsZero() {
		existing.CreatedAt = rec.CreatedAt
	}
	snap.Alerts[rec.Fingerprint] = existing
	return s.Save(ctx, snap)
}

// MarkAlertDelivered implements StateStore.
func (s *FileStore) MarkAlertDelivered(ctx context.Context, fingerprint string, at time.Time) error {
	snap, err := s.Load(ctx)
	if err != nil {
		return err
	}
	rec, ok := snap.Alerts[fingerprint]
	if !ok {
		return fmt.Errorf("%w: alert %s", ErrNotFound, fingerprint)
	}
	rec.Delivered = true
	rec.DeliveredAt = at.UTC()
	rec.LastError = ""
	snap.Alerts[fingerprint] = rec
	return s.Save(ctx, snap)
}

// AlertRecordFor implements StateStore.
func (s *FileStore) AlertRecordFor(ctx context.Context, fingerprint string) (domain.AlertRecord, error) {
	snap, err := s.Load(ctx)
	if err != nil {
		return domain.AlertRecord{}, err
	}
	rec, ok := snap.Alerts[fingerprint]
	if !ok {
		return domain.AlertRecord{}, fmt.Errorf("%w: alert %s", ErrNotFound, fingerprint)
	}
	return rec, nil
}

// ListAlerts implements StateStore, newest first.
func (s *FileStore) ListAlerts(ctx context.Context, limit int) ([]domain.AlertRecord, error) {
	snap, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.AlertRecord, 0, len(snap.Alerts))
	for _, rec := range snap.Alerts {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		// Undelivered attempts sort first so that a failed delivery is the
		// first thing an operator sees.
		if out[i].Delivered != out[j].Delivered {
			return !out[i].Delivered
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// writeCanonicalFile writes JSON deterministically and atomically.
//
// The write goes to a temporary file in the same directory and is then renamed,
// so a reader never observes a partially written file and an interrupted run
// cannot corrupt state. A trailing newline keeps the file well-behaved in
// version control.
func writeCanonicalFile(path string, v any) error {
	body, err := canon.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(body); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	// Durability requires the data to reach the disk before the rename makes
	// it visible; without this, a power loss can leave an empty file in place
	// of the previous good one.
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	// Windows will not rename onto an existing file, so the previous file is
	// removed first. The window is small and the replacement is complete, and
	// the alternative - a non-atomic write - risks losing all state.
	if err := replaceFile(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// filterUsablePrograms drops records that cannot be used.
//
// A record without an identifier or a slug is unusable: it cannot be matched
// against a future observation, so keeping it would let it accumulate forever
// and pretend to be coverage.
func filterUsablePrograms(in map[string]domain.Program) map[string]domain.Program {
	out := make(map[string]domain.Program, len(in))
	for id, p := range in {
		if p.Slug == "" && id == "" {
			continue
		}
		if p.ID == "" {
			p.ID = id
		}
		out[id] = p
	}
	return out
}

// sanitizeName makes an arbitrary identifier safe as a filename.
func sanitizeName(in string) string {
	if in == "" {
		return "unnamed"
	}
	out := make([]rune, 0, len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	// A leading dot would hide the file and could collide with the directory
	// itself on some systems.
	trimmed := string(out)
	for len(trimmed) > 0 && trimmed[0] == '.' {
		trimmed = trimmed[1:]
	}
	if trimmed == "" {
		return "unnamed"
	}
	return trimmed
}
