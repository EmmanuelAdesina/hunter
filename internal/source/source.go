// Package source defines the boundary between the engine and the outside world.
//
// Adapters live in subpackages and implement domain.ProgramSource. Nothing
// outside this package may depend on a concrete adapter, and no adapter may
// import policy, diffing, scoring, or alerting. That inversion is what lets a
// second platform be added without touching the engine.
package source

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Sentinel errors shared by adapters. Adapters wrap these with context rather
// than inventing new error identities, so that callers can classify failures
// without string matching.
var (
	// ErrNotFound means the resource does not exist.
	ErrNotFound = errors.New("source: not found")
	// ErrUnavailable means the source could not be reached or returned a
	// retryable failure.
	ErrUnavailable = errors.New("source: unavailable")
	// ErrRateLimited means the source asked us to slow down.
	ErrRateLimited = errors.New("source: rate limited")
	// ErrParse means the response was retrieved but could not be understood.
	//
	// This is the error that matters most. A parse failure must never be
	// downgraded into an empty result, because empty results flow into policy
	// as "the program has no requirements".
	ErrParse = errors.New("source: parse failure")
	// ErrConfig means the adapter is misconfigured.
	ErrConfig = errors.New("source: configuration error")
)

// HTTPStatusError carries the status code alongside a sentinel error.
type HTTPStatusError struct {
	StatusCode int
	Status     string
	URL        string
	RetryAfter time.Duration
	Err        error
}

func (e *HTTPStatusError) Error() string {
	switch {
	case e.StatusCode == 0 && e.Status != "":
		// A transport-level failure carries no status code, so reporting
		// "http 0" would be actively misleading about what went wrong.
		return fmt.Sprintf("%s from %s", e.Status, e.URL)
	case e.RetryAfter > 0:
		return fmt.Sprintf("http %d from %s (retry after %s)", e.StatusCode, e.URL, e.RetryAfter)
	default:
		return fmt.Sprintf("http %d from %s", e.StatusCode, e.URL)
	}
}

func (e *HTTPStatusError) Unwrap() error { return e.Err }

// IsRetryable reports whether an error is worth retrying.
//
// Only transient conditions qualify. Retrying a 404 or a parse failure wastes
// requests and, worse, delays the discovery of a genuine upstream change.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var se *HTTPStatusError
	if errors.As(err, &se) {
		switch {
		case errors.Is(err, ErrRateLimited):
			return true
		case errors.Is(err, ErrUnavailable):
			return se.StatusCode >= 500 || se.StatusCode == 408 || se.StatusCode == 429
		default:
			return false
		}
	}
	// Context cancellation and deadline expiry are not retryable: the caller
	// has already decided the work should stop.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRateLimited)
}

// Registry holds the available adapters keyed by name.
//
// Registration happens in one place so that a new source is a single call, and
// so that enabling it stays a configuration change rather than a code change.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]func() (domain.ProgramSource, error)
	names     []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]func() (domain.ProgramSource, error))}
}

// Register adds an adapter factory under a name. Re-registering a name
// replaces the previous factory, which keeps tests simple.
func (r *Registry) Register(name string, f func() (domain.ProgramSource, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; !exists {
		r.names = append(r.names, name)
	}
	r.factories[name] = f
}

// Names returns the registered adapter names in sorted order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]string(nil), r.names...)
	sort.Strings(out)
	return out
}

// Build instantiates the named adapters.
//
// One adapter failing to construct is reported without preventing the others
// from starting: a single broken integration should degrade coverage, not end
// the scan.
func (r *Registry) Build(names []string) ([]domain.ProgramSource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]domain.ProgramSource, 0, len(names))
	var errs []error
	for _, name := range names {
		f, ok := r.factories[name]
		if !ok {
			errs = append(errs, fmt.Errorf("%w: no adapter named %q (known: %v)", ErrConfig, name, r.names))
			continue
		}
		src, err := f()
		if err != nil {
			errs = append(errs, fmt.Errorf("build %q: %w", name, err))
			continue
		}
		out = append(out, src)
	}
	return out, errors.Join(errs...)
}
