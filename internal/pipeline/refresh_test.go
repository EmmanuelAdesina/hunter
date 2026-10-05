package pipeline

import (
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

const detailRefreshProfile = `
profile:
  name: detail-refresh-test
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
  notifications:
    alert_on_new_programs: true
    new_program_window: 24h
    change_windows:
      default: 168h
  scan:
    details_refresh_interval: 24h
`

func TestNeedsDetailAdaptsRefreshForRecentlyObservedMovement(t *testing.T) {
	profile, err := config.Parse([]byte(detailRefreshProfile))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	fetchedAt := base.Add(2 * time.Hour)
	prev := domain.Program{
		DetailsFetchedAt: &fetchedAt,
		ScopeChanged: domain.NewObservationInterval(
			base, fetchedAt,
		),
	}
	ref := domain.ProgramRef{}

	now := fetchedAt.Add(5 * time.Hour)
	scanner := &Scanner{cfg: Config{
		Profile: profile,
		Now:     func() time.Time { return now },
	}}
	if scanner.needsDetail(ref, prev, true) {
		t.Fatal("detail refresh ran before the adapted six-hour interval")
	}

	now = fetchedAt.Add(6 * time.Hour)
	if !scanner.needsDetail(ref, prev, true) {
		t.Fatal("detail refresh did not run at one quarter of the 24-hour interval")
	}
}

func TestNeedsDetailKeepsNormalIntervalForStableAndUnknownEvidence(t *testing.T) {
	profile, err := config.Parse([]byte(detailRefreshProfile))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	fetchedAt := base
	prev := domain.Program{DetailsFetchedAt: &fetchedAt}
	ref := domain.ProgramRef{}
	now := base.Add(23*time.Hour + 59*time.Minute)
	scanner := &Scanner{cfg: Config{
		Profile: profile,
		Now:     func() time.Time { return now },
	}}
	if scanner.needsDetail(ref, prev, true) {
		t.Fatal("stable record refreshed before the configured 24-hour interval")
	}
	now = base.Add(24 * time.Hour)
	if !scanner.needsDetail(ref, prev, true) {
		t.Fatal("stable record did not refresh at the configured interval")
	}

	// A short test interval remains exact so scanAt-style tests can force detail
	// reads with strictly increasing clocks rather than waiting for the adaptive
	// production cadence.
	profile.Scan.DetailsRefreshInterval = 1
	now = base.Add(time.Nanosecond)
	if !scanner.needsDetail(ref, prev, true) {
		t.Fatal("explicit nanosecond test interval was not honored")
	}
}
