package domain

import (
	"context"
	"time"
)

// ProgramRef is a lightweight handle to a program discovered from a source.
//
// Discovery returns references rather than full programs so that the caller can
// decide which ones are worth the cost of a detail fetch. On a platform with
// several hundred programs, fetching every detail page on every five-minute scan
// would be both slow and rude.
type ProgramRef struct {
	// Source is the adapter name that produced this reference.
	Source string `json:"source"`

	// ID is the source-local stable identifier.
	ID string `json:"id"`

	// Slug is the URL slug, when the source uses one.
	Slug string `json:"slug"`

	// Name is a display hint from the listing, used only for logging and for
	// cheap early filtering.
	Name string `json:"name,omitempty"`

	// URL is the canonical public page.
	URL string `json:"url,omitempty"`

	// Listing carries every fact the listing page alone exposes, which is what
	// lets the pipeline decide whether a detail fetch is warranted.
	Listing Listing `json:"listing"`

	// ListingUpdatedAt is the source.s coarse update marker from the listing.
	ListingUpdatedAt *time.Time `json:"listing_updated_at,omitempty"`

	// SubmittedReports carries the listing-level competition signal when the
	// source publishes one without requiring a detail fetch.
	SubmittedReports *int `json:"submitted_reports,omitempty"`

	// SubmittedReportsKnown distinguishes a real zero from an absent value.
	SubmittedReportsKnown bool `json:"submitted_reports_known"`
}

// Key returns the globally unique key for the referenced program.
func (r ProgramRef) Key() string { return r.Source + ":" + r.ID }

// ProgramSource discovers and retrieves programs from one upstream platform.
//
// The interface is intentionally narrow and free of any domain vocabulary
// beyond the canonical model, so that adding HackerOne, Bugcrowd, or an
// authorized feed later is an adapter-only change. Nothing outside the source
// package may depend on a concrete implementation.
type ProgramSource interface {
	// Name is the stable adapter identifier, e.g. "hackenproof".
	Name() string

	// Discover lists the programs currently visible to the system.
	//
	// Implementations must tolerate partial failure: a page that cannot be
	// fetched should yield the references recovered so far together with an
	// error, so that a transient outage degrades coverage instead of ending
	// the scan.
	Discover(ctx Context) ([]ProgramRef, error)

	// Fetch retrieves the full public record for one program.
	Fetch(ctx Context, ref ProgramRef) (RawProgram, error)

	// Capabilities describes limits the caller should respect, e.g. whether
	// concurrent fetches are permitted.
	Capabilities() SourceCapabilities
}

// Context is the cancellation and deadline carrier passed to every source
// operation.
type Context = context.Context

// SourceCapabilities describes the operational limits of a source adapter.
// Policy for concurrency and pacing is derived from these values rather than
// hard-coded in the pipeline.
type SourceCapabilities struct {
	// MaxConcurrent bounds simultaneous in-flight requests.
	MaxConcurrent int `json:"max_concurrent"`

	// MinRequestInterval is the minimum spacing between requests.
	MinRequestInterval time.Duration `json:"min_request_interval"`

	// HasStableIDs reports whether the source exposes durable per-program
	// identifiers that do not change across renames. When false, adapters
	// must use slugs as identity.
	HasStableIDs bool `json:"has_stable_ids"`

	// SupportsIncrementalFetch reports whether the source can be asked for
	// only what changed. When false, the pipeline must diff everything.
	SupportsIncrementalFetch bool `json:"supports_incremental_fetch"`

	// DetailFields lists which access-critical facts the source reliably
	// publishes. It documents adapter limitations in a machine-readable way.
	DetailFields []string `json:"detail_fields,omitempty"`
}

// RawProgram is an adapter's untranslated view of a program.
//
// It exists so that normalization can be tested and evolved independently of
// any particular upstream. Every field is a pointer or an explicit tri-state
// because "the source did not say" and "the source said no" are different
// inputs to policy and must not be conflated by the transport layer.
type RawProgram struct {
	// Ref is the reference this record was fetched for.
	Ref ProgramRef `json:"ref"`

	// Parsed reports whether the adapter understood the record at all. When
	// false the pipeline records the failure and skips the program rather than
	// treating absent fields as absent requirements.
	Parsed bool `json:"parsed"`

	// Issues lists human-readable parse problems.
	Issues []string `json:"issues,omitempty"`

	// Identity.
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`

	// Lifecycle. Status and State are the source's own vocabulary.
	Status   string   `json:"status,omitempty"`
	State    string   `json:"state,omitempty"`
	RawDates RawDates `json:"dates"`

	// Access gates. Each is tri-state.
	Reputation ReputationGate `json:"reputation"`
	Fee        FeeGate        `json:"fee"`
	KYC        Tri            `json:"kyc"`
	POC        Tri            `json:"poc"`

	// Bounty bounds as decimal strings, preserving source precision.
	MinBountyRaw   string `json:"min_bounty_raw,omitempty"`
	MaxBountyRaw   string `json:"max_bounty_raw,omitempty"`
	RewardsPaidRaw string `json:"rewards_paid_raw,omitempty"`

	// Competition signal.
	SubmittedReports      *int `json:"submitted_reports,omitempty"`
	SubmittedReportsKnown bool `json:"submitted_reports_known"`

	// Classification labels as the source presents them.
	CategoriesRaw   []string `json:"categories_raw,omitempty"`
	ProjectTypesRaw []string `json:"project_types_raw,omitempty"`
	TechnologiesRaw []string `json:"technologies_raw,omitempty"`
	LanguagesRaw    []string `json:"languages_raw,omitempty"`

	// Scopes is the raw asset list.
	Scopes []RawScope `json:"scopes,omitempty"`

	// Prose, kept for classification only.
	Description string `json:"description,omitempty"`
	ScopeNotes  string `json:"scope_notes,omitempty"`
	Rules       string `json:"rules,omitempty"`
}

// RawDates holds date strings as the source presents them. Dates are parsed in
// normalization so that an unparseable date becomes an unknown timestamp rather
// than a fabricated one.
type RawDates struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
	// Updated is the source's coarse last-modified marker.
	Updated string `json:"updated,omitempty"`
	// Unending marks programs that never expire.
	Unending bool `json:"unending"`
}

// RawScope is one asset as the source presents it.
type RawScope struct {
	Title       string `json:"title,omitempty"`
	Target      string `json:"target,omitempty"`
	Description string `json:"description,omitempty"`
	OutOfScope  bool   `json:"out_of_scope"`
	Criticality string `json:"criticality,omitempty"`
	ID          string `json:"id,omitempty"`
}

// Listing carries the facts observable from a program's listing page alone.
//
// This is the second tier of a two-tier read. The listing page is cheap and is
// fetched for every program on every scan, so anything it exposes can be used to
// decide whether the expensive detail fetch is warranted at all. On this
// platform that covers new programs, lifecycle state, bounty changes, the
// submission count, and a scope revision marker - which is enough to detect a
// change without reading a single detail page.
type Listing struct {
	// UpdatedAt is the source's coarse last-modified marker.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	// RenderCounter is the source's per-render page counter.
	//
	// It is captured but deliberately excluded from change detection: on this
	// platform it increments on every page render, so treating it as a revision
	// would mark a large share of programs as changed on every single scan and
	// defeat the cheap tier. It is recorded because a future source may publish
	// a genuinely stable equivalent under the same key.
	RenderCounter int `json:"render_counter,omitempty"`

	// Status and State are the source's lifecycle vocabulary.
	Status string `json:"status,omitempty"`
	State  string `json:"state,omitempty"`

	// RewardRaw is the displayed bounty, exactly as published.
	RewardRaw string `json:"reward_raw,omitempty"`

	// RewardsPaidRaw is the displayed total paid out.
	RewardsPaidRaw string `json:"rewards_paid_raw,omitempty"`

	// ActivityStatus is the source's human-facing activity label.
	ActivityStatus string `json:"activity_status,omitempty"`

	// Unending marks programs that never expire.
	Unending bool `json:"unending"`

	// Categories, ProjectTypes, and Technologies are the source's own
	// classification labels, enough to establish crypto character without a
	// detail fetch.
	Categories   []string `json:"categories,omitempty"`
	ProjectTypes []string `json:"project_types,omitempty"`
	Technologies []string `json:"technologies,omitempty"`

	// SubmittedReports is the listing-level competition signal.
	SubmittedReports      *int `json:"submitted_reports,omitempty"`
	SubmittedReportsKnown bool `json:"submitted_reports_known"`
}

// Equal compares two listing observations.
//
// Only the fields that can indicate a change are compared. Comparing the
// submission count is deliberately included: a jump in submissions means other
// researchers are actively working a program, which is exactly when fresh
// eligibility data matters most.
// Equal reports whether two listing observations match exactly.
//
// The render counter is excluded here too, for the same reason it is excluded
// from ChangedSince: it changes on every page render, so including it would make
// equality almost never hold and render the comparison useless. It remains
// available on the struct for diagnostics.
func (l Listing) Equal(other Listing) bool {
	return equalTimePtr(l.UpdatedAt, other.UpdatedAt) &&
		l.Status == other.Status &&
		l.State == other.State &&
		l.RewardRaw == other.RewardRaw &&
		l.RewardsPaidRaw == other.RewardsPaidRaw &&
		l.ActivityStatus == other.ActivityStatus &&
		l.Unending == other.Unending &&
		equalStrings(l.Categories, other.Categories) &&
		equalStrings(l.ProjectTypes, other.ProjectTypes) &&
		equalStrings(l.Technologies, other.Technologies) &&
		l.SubmittedReportsKnown == other.SubmittedReportsKnown &&
		equalIntPtr(l.SubmittedReports, other.SubmittedReports)
}

func equalTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func equalIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Summary renders the listing observation for a change record.
func (l Listing) Summary() string {
	parts := make([]string, 0, 4)
	if l.Status != "" {
		parts = append(parts, "status "+l.Status)
	}
	if l.RewardRaw != "" {
		parts = append(parts, "bounty "+l.RewardRaw)
	}
	if l.RenderCounter > 0 {
		parts = append(parts, "render counter "+itoa(l.RenderCounter))
	}
	if l.SubmittedReportsKnown && l.SubmittedReports != nil {
		parts = append(parts, itoa(*l.SubmittedReports)+" submissions")
	}
	if len(parts) == 0 {
		return "no listing data"
	}
	return joinComma(parts)
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ChangedSince reports whether the listing shows something that could warrant a
// detail read.
//
// The submission count is deliberately excluded. It rises continuously on active
// programs, so treating it as a change signal would make every program look
// modified on every scan and defeat the cheap tier entirely. A rising count is
// recorded as an observation and used for triage, but it says nothing about
// whether scope or requirements moved.
func (l Listing) ChangedSince(other Listing) bool {
	// RenderCounter is deliberately absent. It increments on every page render
	// on this platform, so including it would mark a large share of programs as
	// changed on every scan and force the expensive tier to run constantly,
	// which is exactly what the cheap tier exists to prevent.
	return !equalTimePtr(l.UpdatedAt, other.UpdatedAt) ||
		l.Status != other.Status ||
		l.State != other.State ||
		l.RewardRaw != other.RewardRaw ||
		l.RewardsPaidRaw != other.RewardsPaidRaw ||
		l.ActivityStatus != other.ActivityStatus ||
		l.Unending != other.Unending ||
		!equalStrings(l.Categories, other.Categories) ||
		!equalStrings(l.ProjectTypes, other.ProjectTypes) ||
		!equalStrings(l.Technologies, other.Technologies)
}

// SubmissionsChanged reports whether the observed submission count moved.
func (l Listing) SubmissionsChanged(other Listing) bool {
	if l.SubmittedReportsKnown != other.SubmittedReportsKnown {
		return true
	}
	if !l.SubmittedReportsKnown {
		return false
	}
	switch {
	case l.SubmittedReports == nil && other.SubmittedReports == nil:
		return false
	case l.SubmittedReports == nil || other.SubmittedReports == nil:
		return true
	default:
		return *l.SubmittedReports != *other.SubmittedReports
	}
}

// SubmissionSummary renders an observed submission count for display.
func (l Listing) SubmissionSummary() string {
	if !l.SubmittedReportsKnown {
		return "not published"
	}
	if l.SubmittedReports == nil {
		return "not published"
	}
	return itoa(*l.SubmittedReports) + " submissions"
}
