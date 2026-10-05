package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WindowStatus is a window's lifecycle position.
//
// Only two states are persisted, and both are derived from evidence rather than
// scheduled. A persisted OPENED/FRESH/AGING/CROWDED ladder would be state that
// must be migrated, could get stuck mid-transition, and could contradict the
// observations that justify it. Everything a reader actually wants to know -
// how old is this, how crowded has it become - is computed from the stored
// evidence on demand, so it cannot drift out of step with the facts.
type WindowStatus string

const (
	// WindowOpen means the window is still inside its recency window.
	WindowOpen WindowStatus = "open"

	// WindowExpired means the window's recency has elapsed, or it has been crowded
	// past the configured threshold.
	WindowExpired WindowStatus = "expired"
)

// OpportunityWindow is a bounded interval during which an existing program
// became newly reachable, newly testable, or newly better compensated.
//
// # What a window is
//
// The central distinction this system turns on is between the age of a program
// and the age of an opportunity. A five-year-old program whose API scope was
// extended nine minutes ago is a fresh research target; the same program with no
// change in five years is not. The window is the second clock, and it is the one
// a researcher acts on.
//
// # What a window is not
//
// It is not a prediction. Nothing here estimates whether a bug exists, whether it
// will be found, or whether the window is "good". It records that a set of
// observed field movements happened inside a bounded interval, and it measures
// how much the platform's own submission count has moved since.
type OpportunityWindow struct {
	// ID is the window's event identity, derived from the program and the
	// evidence of the transition that opened it.
	//
	// It is deliberately NOT program plus change kind. A program can add an API,
	// lose it, and add it again; those are three different transitions and the
	// third is a genuinely new opening that other researchers have not seen. Two
	// windows opened by identical change content are therefore distinguishable,
	// and two observations of the same transition are not.
	ID string `json:"id"`

	// ProgramID is the program the opportunity belongs to.
	ProgramID string `json:"program_id"`

	// ProgramName is carried for display, so `hunter windows` needs no join.
	ProgramName string `json:"program_name,omitempty"`

	// Triggers lists the change kinds that opened this window, sorted.
	//
	// A window holds more than one trigger when several changes fell inside the
	// same bundling interval. The individual deltas remain authoritative; this is
	// the summary of what kinds they were.
	Triggers []string `json:"triggers,omitempty"`

	// Observed is the interval within which the change was seen to happen.
	//
	// It is an interval rather than a timestamp throughout, for the same reason
	// everywhere else in this model: the system compares two observations and does
	// not observe the instant between them.
	Observed ObservationInterval `json:"observed"`

	// Deltas is the atomic, directional evidence that opened the window.
	//
	// Nothing is fused. "Access improved" is a conclusion drawn from these, and it
	// belongs to whoever reads them, not to the record.
	Deltas Deltas `json:"deltas,omitempty"`

	// AssetsAdded lists the identifiers newly in scope, when the window is about
	// scope.
	AssetsAdded []string `json:"assets_added,omitempty"`

	// BaselineSubmissions is the platform's submission count observed at the moment
	// the transition was detected. It is an observation, not a measurement of
	// competition.
	BaselineSubmissions *int `json:"baseline_submissions,omitempty"`

	// CurrentSubmissions is the most recently observed count.
	CurrentSubmissions *int `json:"current_submissions,omitempty"`

	// SubmissionsSinceOpen is the signed movement since the window opened.
	//
	// It is signed because the platform's count falls as well as rises: reports are
	// triaged out, duplicates are merged, spam is removed. A count that can only
	// increase would make a falling number look like an arithmetic error, and a
	// negative movement is real evidence about the window.
	SubmissionsSinceOpen *int `json:"submissions_since_open,omitempty"`

	// OpenedScanID identifies the scan that first observed the transition.
	OpenedScanID string `json:"opened_scan_id,omitempty"`

	// Notified records that an alert was raised for this window, so a retry does
	// not raise a second one.
	Notified bool `json:"notified"`

	// NotifiedAt is when the alert was raised.
	NotifiedAt *time.Time `json:"notified_at,omitempty"`
}

// OpportunityWindowOptions tune window derivation.
type OpportunityWindowOptions struct {
	// Now supplies the current time.
	Now time.Time

	// BundleWindow is how far apart two changes may fall and still be bundled into
	// one window. Zero disables bundling, giving one window per scan.
	BundleWindow time.Duration

	// MaxAge is how old a window may be before it expires.
	MaxAge time.Duration

	// MaxPostChangeSubmissions is how many submissions may accumulate after the
	// window opened before it is considered crowded. Zero disables the check.
	MaxPostChangeSubmissions int

	// ScanID identifies the current scan.
	ScanID string
}

// NewOpportunityWindow derives a window from an observed transition.
//
// The identity is a hash over the program and the evidence, so it is stable across
// scans observing the same transition and distinct across transitions that happen
// to look identical. Time is included through the interval's lower bound, which is
// the observation that preceded the change: that is what separates a program that
// added an API in March from one that removed it in June and added it back.
func NewOpportunityWindow(programID, programName string, observed ObservationInterval, ds Deltas, opts OpportunityWindowOptions) OpportunityWindow {
	w := OpportunityWindow{
		ProgramID:    programID,
		ProgramName:  programName,
		Observed:     observed,
		Deltas:       ds,
		Triggers:     ds.Kinds(),
		OpenedScanID: opts.ScanID,
	}
	w.ID = windowIdentity(programID, observed, ds)
	return w
}

func windowIdentity(programID string, observed ObservationInterval, ds Deltas) string {
	h := sha256.New()
	fmt.Fprintf(h, "hunter/window/v1\nprogram=%s\n", programID)
	if observed.Known() {
		fmt.Fprintf(h, "not_before=%s\n", observed.NotBefore.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(h, "deltas=%s\n", ds.Identity())
	return hex.EncodeToString(h.Sum(nil))
}

// ShortID returns a human-usable identifier for logs and terminals.
func (w OpportunityWindow) ShortID() string {
	if len(w.ID) <= 12 {
		return w.ID
	}
	return w.ID[:12]
}

// Age returns the bounded age of the window, and whether it is bounded at all.
func (w OpportunityWindow) Age(now time.Time) (time.Duration, bool) {
	if !w.Observed.Known() {
		return 0, false
	}
	return w.Observed.OldestAge(now), true
}

// Status returns the window's lifecycle position.
//
// Both inputs are published alongside it, so a reader is never told "crowded"
// without being told the count that made it so.
func (w OpportunityWindow) Status(now time.Time, opts OpportunityWindowOptions) WindowStatus {
	age, known := w.Age(now)
	if !known {
		// An unbounded window cannot be placed in time, so it cannot be shown to be
		// fresh. It is reported as expired rather than open, because treating it as
		// open would assert a recency the evidence does not support.
		return WindowExpired
	}
	if opts.MaxAge > 0 && age > opts.MaxAge {
		return WindowExpired
	}
	if opts.MaxPostChangeSubmissions > 0 && w.SubmissionsSinceOpen != nil &&
		*w.SubmissionsSinceOpen >= opts.MaxPostChangeSubmissions {
		return WindowExpired
	}
	return WindowOpen
}

// Observe updates the window's competition signals from a fresh observation.
//
// The baseline is set once, on the scan that opened the window, and never
// rewritten. Rewriting it would silently move the origin and make the measured
// movement meaningless, so a second call only refreshes the current count.
func (w *OpportunityWindow) Observe(submissions *int, known bool) {
	if !known || submissions == nil {
		return
	}
	current := *submissions
	if w.BaselineSubmissions == nil {
		baseline := current
		w.BaselineSubmissions = &baseline
	}
	w.CurrentSubmissions = &current
	delta := current - *w.BaselineSubmissions
	w.SubmissionsSinceOpen = &delta
}

// ImprovedDeltas returns the deltas that moved in the researcher's favour.
func (w OpportunityWindow) ImprovedDeltas() Deltas { return w.Deltas.Improved() }

// DegradedDeltas returns the deltas that moved against the researcher.
func (w OpportunityWindow) DegradedDeltas() Deltas { return w.Deltas.Degraded() }

// AssetsAddedFromDeltas collects every newly in-scope identifier in the window.
func (w OpportunityWindow) AssetsAddedFromDeltas() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(w.Deltas))
	for _, d := range w.Deltas {
		for _, a := range d.Assets {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// Describe renders the window's headline claim for a notification.
//
// The wording is chosen to be defensible under questioning. It states what was
// observed and how wide the bound is, and it never asserts a precise change time,
// an absence of competition, or a likelihood of finding anything.
func (w OpportunityWindow) Describe(now time.Time) string {
	var b strings.Builder
	b.WriteString("RESEARCH WINDOW")
	if _, ok := w.Age(now); ok {
		b.WriteString(" - " + w.Observed.Humanize(now))
	} else {
		b.WriteString(" - age unknown")
	}
	b.WriteString("\n")
	if w.ProgramName != "" {
		b.WriteString("Program: " + w.ProgramName + "\n")
	}
	return b.String()
}
