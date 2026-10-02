package config

import (
	"fmt"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// stringDuration is a duration written as a Go duration string in YAML, e.g.
// "30s". Using a string rather than time.Duration keeps the profile readable
// and makes an unparseable value a validation error instead of a silent zero.
type stringDuration time.Duration

func (d stringDuration) Value() time.Duration { return time.Duration(d) }

func (d stringDuration) String() string { return time.Duration(d).String() }

// MarshalYAML renders the duration back as its string form.
func (d stringDuration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// UnmarshalYAML parses a duration string, rejecting bare numbers so that a unit
// is never forgotten.
func (d *stringDuration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("duration must be a string such as \"30s\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = stringDuration(v)
	return nil
}

// stringDurationValue is an alias used by accessors that return a plain
// duration for callers outside this package.
type stringDurationValue = time.Duration

// Default operational values. These are documented defaults rather than policy:
// every one of them can be overridden from the profile.
const (
	defaultUserAgent     = "hunter-research-monitor/1.0 (+personal bug-bounty opportunity monitor; contact: researcher)"
	defaultTimeout       = 20 * time.Second
	defaultRetryBase     = 1 * time.Second
	defaultMaxRetryDelay = 30 * time.Second
	defaultMinInterval   = 500 * time.Millisecond
	defaultFreshWindow   = 7 * 24 * time.Hour
)

// Freshness thresholds are exposed as durations.
func (p *Profile) FreshProgramWindow() time.Duration {
	if p.Freshness.FreshProgramWindow == 0 {
		return defaultFreshWindow
	}
	return time.Duration(p.Freshness.FreshProgramWindow)
}

// FreshScopeWindow returns the window within which a scope change counts as
// recent.
func (p *Profile) FreshScopeWindow() time.Duration {
	if p.Freshness.FreshScopeWindow == 0 {
		return defaultFreshWindow
	}
	return time.Duration(p.Freshness.FreshScopeWindow)
}

// StaleProgramAge returns the age beyond which a program's priority decays.
func (p *Profile) StaleProgramAge() time.Duration {
	return time.Duration(p.Freshness.StaleProgramAge)
}

// ScanDuration returns a scan-level tuning value by name.
func (p *Profile) ScanDuration(field string) time.Duration {
	switch field {
	case "request_timeout":
		return time.Duration(p.Scan.RequestTimeout)
	case "retry_base_delay":
		return time.Duration(p.Scan.RetryBaseDelay)
	case "max_retry_delay":
		return time.Duration(p.Scan.MaxRetryDelay)
	case "min_request_interval":
		return time.Duration(p.Scan.MinRequestInterval)
	default:
		return 0
	}
}

// AllowedStates returns the accepted lifecycle states.
func (p *Profile) AllowedStates() []domain.ProgramState { return p.allowedStates }

// AlertOnStates returns the states that warrant an alert.
func (p *Profile) AlertOnStates() []domain.ProgramState { return p.alertOnStates }

// MinSeverity returns the lowest alertable severity.
func (p *Profile) MinSeverity() domain.Severity { return p.Notifications.MinSeverity }

// DetailsRefreshInterval returns how long a detail record may go unrefreshed,
// defaulting to a day.
//
// The default is not arbitrary. Access gates change rarely, so re-reading every
// detail page every five minutes would spend thousands of requests an hour to
// confirm facts that have not moved. A day also bounds how long the system can
// carry a change the listing does not expose.
func (p *Profile) DetailsRefreshInterval() time.Duration {
	if p.Scan.DetailsRefreshInterval == 0 {
		return 24 * time.Hour
	}
	return time.Duration(p.Scan.DetailsRefreshInterval)
}

// FetchDetailsOnListingChange reports whether a listing difference triggers a
// detail read. It defaults to true, because the whole point of the cheap tier is
// to decide when the expensive tier is needed.
func (p *Profile) FetchDetailsOnListingChange() bool {
	return p.Scan.FetchDetailsOnListingChange
}
