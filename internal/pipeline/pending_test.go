package pipeline_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
)

// failListAlertsStore simulates a notification-retry read failure while every
// other store operation behaves normally.
type failListAlertsStore struct {
	state.StateStore
	err error
}

func (s *failListAlertsStore) ListAlerts(ctx context.Context, limit int) ([]domain.AlertRecord, error) {
	return nil, s.err
}

// A failed pending-alert retry must not fail an otherwise healthy observation
// scan. The scan-start Load is the hard guard against corrupt state; by the
// time pendingAlerts runs, discovery, evaluation, alerting, and persistence
// have all succeeded, and the pending records remain stored for the next scan.
func TestPendingAlertsFailureDoesNotFailHealthyScan(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()

	// First scan populates state normally.
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	store := &failListAlertsStore{StateStore: state.NewFileStore(dir), err: errors.New("simulated retry-read failure")}

	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Store = store
	})
	if err != nil {
		t.Fatalf("a pending-retry read failure must not fail the scan: %v", err)
	}
	if res.Metrics.Errors != 0 {
		t.Errorf("metrics errors = %d, want 0: the retry failure must not count against the observation", res.Metrics.Errors)
	}
	if res.Metrics.Evaluated == 0 {
		t.Error("expected evaluated programs in a healthy scan")
	}
}
