package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

func TestLoadRecoversInterruptedSaveTransaction(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	snap := NewSnapshot()
	snap.LastScanID = "20261001T120000Z"
	snap.LastScanAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	snap.Programs["fake:alpha"] = domain.Program{ID: "fake:alpha", Slug: "alpha"}
	snap.Alerts["fingerprint-alpha"] = domain.AlertRecord{
		Fingerprint: "fingerprint-alpha",
		ProgramID:   "fake:alpha",
		Subject:     "new program alert",
		CreatedAt:   snap.LastScanAt,
		Delivered:   false,
	}
	snap.EnsureMaps()

	txn := saveTransaction{
		Version: CurrentVersion,
		Programs: programsFile{
			Version: CurrentVersion, LastScanID: snap.LastScanID,
			LastScanAt: snap.LastScanAt, Programs: snap.Programs,
		},
		Alerts:  alertsFile{Version: CurrentVersion, Alerts: snap.Alerts},
		Windows: windowsFile{Version: CurrentVersion, Windows: snap.Windows},
		Digest:  snap.MaterialDigest(),
	}
	if err := writeCanonicalFile(store.txnPath, txn); err != nil {
		t.Fatalf("write transaction journal: %v", err)
	}
	// Simulate a crash after the program file was replaced but before the
	// pending alert and the rest of the snapshot were written.
	if err := writeCanonicalFile(store.programsPath, txn.Programs); err != nil {
		t.Fatalf("write partial program state: %v", err)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load should recover the pending transaction: %v", err)
	}
	if _, ok := loaded.Programs["fake:alpha"]; !ok {
		t.Fatal("program from the committed transaction is missing")
	}
	alert, ok := loaded.Alerts["fingerprint-alpha"]
	if !ok || alert.Delivered {
		t.Fatalf("pending alert after recovery = %+v, present=%t; want retained and undelivered", alert, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, ".save-transaction.json")); !os.IsNotExist(err) {
		t.Errorf("transaction journal still exists after recovery: %v", err)
	}
	digest, err := os.ReadFile(filepath.Join(dir, "material.sha256"))
	if err != nil {
		t.Fatalf("read material digest: %v", err)
	}
	if string(digest) != txn.Digest+"\n" {
		t.Errorf("material digest = %q, want %q", digest, txn.Digest+"\n")
	}
}
