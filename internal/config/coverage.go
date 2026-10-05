package config

// CoverageConfig governs how the system reacts to losing sight of programs it
// previously knew about.
//
// # Why this exists
//
// Hunter's entire value proposition is noticing that an existing program changed.
// A change on a program that discovery has silently dropped is invisible
// permanently, and nothing else in the system would reveal it: the scan would
// report programs discovered, programs evaluated, alerts generated, errors zero,
// and exit successfully.
//
// That is the specific failure this system's own documentation calls the most
// dangerous outcome for a monitor - silence that cannot be told apart from a
// quiet platform. It is not hypothetical. A single rate-limited listing sweep on a
// platform whose pagination is 33 pages wide loses a tenth of the catalogue while
// the scan still reports success.
//
// # Why it is not simply a count comparison
//
// Comparing discovered against known would fire on every legitimate departure:
// programs end, get unlisted, get renamed. The distinction that matters is
// whether a program was *seen* and *said it was finished* before it went, so
// terminal programs are excluded from the expectation and evicted once their
// absence is confirmed. A live program that vanishes is a fault, not a departure.
//
// A transient loss must also be tolerated. One dropped sweep is a network event;
// two consecutive drops are a fact about the world. GraceSweeps is that
// hysteresis, and it is why AbsentScans is a counter rather than a flag.
type CoverageConfig struct {
	// MinRatio is the fraction of expected programs that must be observed for a
	// sweep to be trusted. Below it the scan is degraded.
	//
	// It is deliberately not 1.0. Pagination occasionally drops a page, and a
	// monitor that treats two lost programs out of three hundred as a failure
	// trains its operator to ignore the alarm. The default leaves room for a
	// single page of a thirty-page sweep.
	MinRatio float64 `yaml:"min_ratio"`

	// GraceSweeps is how many consecutive sweeps a program may be missing before
	// its absence is treated as a fact rather than a transient.
	//
	// One sweep of grace is the minimum that distinguishes a network failure from
	// a departure, because the sweep that discovers the absence is the sweep that
	// failed to deliver the program.
	GraceSweeps int `yaml:"grace_sweeps"`

	// EvictDeparted removes a program from state once it has been absent beyond
	// the grace period. It defaults to true: keeping a program the platform no
	// longer publishes forever would make the coverage denominator grow without
	// bound and guarantee a permanent false alarm.
	EvictDeparted *bool `yaml:"evict_departed"`
}

// evictDeparted reports the effective eviction setting.
func (c CoverageConfig) evictDeparted() bool {
	if c.EvictDeparted == nil {
		return true
	}
	return *c.EvictDeparted
}

func boolPtr(v bool) *bool { return &v }

// CoverageMinRatio returns the floor below which a sweep is untrusted.
func (p *Profile) CoverageMinRatio() float64 {
	if p.Coverage.MinRatio <= 0 || p.Coverage.MinRatio > 1 {
		return defaultCoverageMinRatio
	}
	return p.Coverage.MinRatio
}

// CoverageGraceSweeps returns how many consecutive misses confirm a departure.
func (p *Profile) CoverageGraceSweeps() int {
	if p.Coverage.GraceSweeps <= 0 {
		return defaultCoverageGraceSweeps
	}
	return p.Coverage.GraceSweeps
}

// EvictDeparted reports whether confirmed departures are removed from state.
func (p *Profile) EvictDeparted() bool { return p.Coverage.evictDeparted() }

const (
	// defaultCoverageMinRatio is 0.9.
	//
	// Sized to absorb one dropped listing page out of the roughly thirty a full
	// sweep traverses, while still catching the order-of-magnitude losses that
	// indicate the sweep itself is broken.
	defaultCoverageMinRatio = 0.9

	// defaultCoverageGraceSweeps is 2.
	defaultCoverageGraceSweeps = 2
)
