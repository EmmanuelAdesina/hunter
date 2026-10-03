package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ProgramState is the normalized lifecycle state of a program.
type ProgramState string

const (
	// StateUnknown means the source did not expose a lifecycle state.
	StateUnknown ProgramState = "unknown"
	// StateNew means the program is published but has just launched and is
	// not yet accepting reports at the historical cadence of a live program.
	StateNew ProgramState = "new"
	// StateLive means the program is actively accepting reports.
	StateLive ProgramState = "live"
	// StatePaused means the program is temporarily not accepting reports.
	StatePaused ProgramState = "paused"
	// StateEnded means the program will not accept further reports.
	StateEnded ProgramState = "ended"
	// StateUnlisted means the program is not publicly visible.
	StateUnlisted ProgramState = "unlisted"
)

// ParseProgramState validates a configured state name.
func ParseProgramState(s string) (ProgramState, bool) {
	switch v := ProgramState(NormalizeTag(s)); v {
	case StateUnknown, StateNew, StateLive, StatePaused, StateEnded, StateUnlisted:
		return v, true
	default:
		return StateUnknown, false
	}
}

// ReputationGate describes a program's reputation requirement.
//
// Present is tri-state so that "the program requires 0 reputation" and "the
// source did not tell us" remain distinguishable. Points is only meaningful when
// Present is TriYes.
type ReputationGate struct {
	Present Tri `json:"present"`
	Points  int `json:"points,omitempty"`
}

// Known reports whether the gate was positively observed either way.
func (g ReputationGate) Known() bool { return g.Present.Known() }

// FeeGate describes a program's submission fee in USD.
type FeeGate struct {
	Present Tri     `json:"present"`
	USD     float64 `json:"usd,omitempty"`
}

// Known reports whether the fee was positively observed either way.
func (g FeeGate) Known() bool { return g.Present.Known() }

// Program is the canonical, source-agnostic representation of a bug-bounty
// program.
//
// Everything downstream of normalization reads only this type. Adapters are
// responsible for converting whatever a source publishes into these fields, and
// for leaving a fact tri-state-unknown when the source does not support a
// confident conclusion.
type Program struct {
	// ID is globally unique and stable: "<source>:<source-local-id>".
	ID string `json:"id"`

	// Source identifies the adapter that produced this program.
	Source string `json:"source"`

	// Slug is the source-local stable identifier. Where a source exposes no
	// stable numeric ID, the slug carries identity.
	Slug string `json:"slug"`

	// Name is the human-facing program name.
	Name string `json:"name"`

	// URL is the canonical public page for the program.
	URL string `json:"url"`

	// State is the normalized lifecycle state.
	State ProgramState `json:"state"`

	// RawStatus and RawState preserve the source's own vocabulary so that a
	// human can reconcile a normalized decision against what they see on the
	// page, and so an unrecognized new value is recorded rather than dropped.
	RawStatus string `json:"raw_status,omitempty"`
	RawState  string `json:"raw_state,omitempty"`

	// StartedAt is when the program launched, at the source's resolution.
	StartedAt *time.Time `json:"started_at,omitempty"`

	// EndsAt is when the program stops accepting reports, when stated.
	EndsAt *time.Time `json:"ends_at,omitempty"`

	// IsUnending marks programs that never expire.
	IsUnending bool `json:"is_unending"`

	// SourceUpdatedAt is the source's own last-modified marker. It is coarse
	// (day resolution on this platform) and therefore used only for display,
	// never as the sole basis for change detection.
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`

	// FirstSeenAt is when this system first observed the program. It is the
	// only trustworthy program-age signal when the source omits a launch date.
	FirstSeenAt time.Time `json:"first_seen_at"`

	// LastSeenAt is when this system last observed the program.
	LastSeenAt time.Time `json:"last_seen_at"`

	// Access gates.
	Reputation ReputationGate `json:"reputation"`
	Fee        FeeGate        `json:"fee"`
	KYC        Tri            `json:"kyc"`
	POC        Tri            `json:"poc"`

	// Bounty bounds in USD. Nil means the source did not state a bound.
	MinBountyUSD *float64 `json:"min_bounty_usd,omitempty"`
	MaxBountyUSD *float64 `json:"max_bounty_usd,omitempty"`

	// RewardsPaidUSD is the total the organization says it has paid out.
	RewardsPaidUSD *float64 `json:"rewards_paid_usd,omitempty"`

	// SubmittedReports is the source's public submission count, a raw
	// competition signal. Nil when the source does not publish one.
	SubmittedReports *int `json:"submitted_reports,omitempty"`

	// SubmittedReportsKnown reports whether the count was actually observed.
	// A zero-valued count and an absent count must not be confused.
	SubmittedReportsKnown bool `json:"submitted_reports_known"`

	// Categories, ProjectTypes, Technologies, and Languages are the source's
	// own classification labels, normalized to lowercase.
	Categories   Tags `json:"categories,omitempty"`
	ProjectTypes Tags `json:"project_types,omitempty"`
	Technologies Tags `json:"technologies,omitempty"`
	Languages    Tags `json:"languages,omitempty"`

	// Targets is the full asset list including out-of-scope entries.
	Targets Targets `json:"targets,omitempty"`

	// Summary is the program description.
	Summary string `json:"summary,omitempty"`

	// ScopeNotes is the in-scope vulnerability description, verbatim.
	// It feeds classification but is never re-rendered into alerts, which
	// keeps alert size bounded.
	ScopeNotes string `json:"-"`

	// ProgramRules is the participant rule set, verbatim. Same handling as
	// ScopeNotes.
	ProgramRules string `json:"-"`

	// CryptoTraits classifies the program against the crypto taxonomy that
	// the profile governs. Empty means the program is not crypto-related or
	// could not be classified.
	CryptoTraits Tags `json:"crypto_traits,omitempty"`

	// CryptoKind is the coarse crypto verdict: not_crypto, platform,
	// smart_contract_only, protocol_research, mixed, or unknown.
	CryptoKind CryptoKind `json:"crypto_kind,omitempty"`

	// SurfaceTags are the technical-surface signals used by policy and
	// scoring, drawn from the configured target-domain vocabulary.
	SurfaceTags Tags `json:"surface_tags,omitempty"`

	// CapabilityTags capture attack-surface characteristics inferred from
	// scope text, such as authentication or payments.
	CapabilityTags Tags `json:"capability_tags,omitempty"`

	// Fingerprints are content hashes over normalized field subsets. Change
	// detection compares these rather than relying on page timestamps.
	ScopeFingerprint       string `json:"scope_fingerprint"`
	RequirementFingerprint string `json:"requirement_fingerprint"`
	MetadataFingerprint    string `json:"metadata_fingerprint"`

	// ParseConfidence records how completely the adapter understood the
	// source. A program parsed at low confidence is quarantined by policy
	// rather than silently trusted.
	ParseConfidence Confidence `json:"parse_confidence"`

	// Listing is the last listing-level observation, used to decide whether a
	// detail fetch is warranted on the next scan.
	Listing ListingSignal `json:"listing"`

	// DetailsFetchedAt is when the detail record behind this program was last
	// read. It is reported rather than hidden, so that a stale access gate is
	// visible to whoever reads the decision.
	DetailsFetchedAt *time.Time `json:"details_fetched_at,omitempty"`

	// ParseIssues lists human-readable descriptions of anything the adapter
	// could not interpret. Order is normalized for stable diffs, but the text
	// itself is preserved verbatim: these are messages for a person, not tags.
	ParseIssues []string `json:"parse_issues,omitempty"`
}

// Confidence reports how completely an adapter understood a source record.
type Confidence string

const (
	// ConfidenceHigh means every access-critical field was positively
	// observed.
	ConfidenceHigh Confidence = "high"
	// ConfidencePartial means the record was understood but some non-critical
	// fields were absent.
	ConfidencePartial Confidence = "partial"
	// ConfidenceLow means access-critical fields are unknown. Policy must
	// quarantine such a program unless the profile opts in.
	ConfidenceLow Confidence = "low"
)

// AcceptsReports reports whether the program is currently accepting reports.
func (p Program) AcceptsReports() bool {
	switch p.State {
	case StateLive, StateNew:
		return true
	default:
		return false
	}
}

// InScopeTargets returns the testable assets.
func (p Program) InScopeTargets() Targets { return p.Targets.InScope() }

// Age returns how long the program has existed, measured from its launch date
// when known and otherwise from first observation. The second result reports
// which basis was used, so triage can explain an estimate honestly.
func (p Program) Age(now time.Time) (d time.Duration, basis AgeBasis) {
	if p.StartedAt != nil {
		if d := now.Sub(*p.StartedAt); d >= 0 {
			return d, AgeFromLaunch
		}
	}
	if !p.FirstSeenAt.IsZero() {
		return now.Sub(p.FirstSeenAt), AgeFromFirstSeen
	}
	return 0, AgeUnknown
}

// AgeBasis explains which timestamp an age estimate came from.
type AgeBasis string

const (
	AgeFromLaunch    AgeBasis = "launch_date"
	AgeFromFirstSeen AgeBasis = "first_seen"
	AgeUnknown       AgeBasis = "unknown"
)

// HasSurface reports whether the program advertises any target domain of
// interest, using the configured vocabulary.
func (p Program) HasSurface(domains ...string) bool { return p.SurfaceTags.HasAny(domains...) }

// computeFingerprints derives the three content fingerprints.
//
// The subsets are deliberately disjoint so that a change produces a change in
// exactly the signal that describes it:
//   - scope: the in-scope asset set
//   - requirements: access gates and participation constraints
//   - metadata: identity, classification, bounty, and state
//
// computeFingerprints is deterministic for a given set of inputs.
func (p *Program) computeFingerprints() {
	p.ScopeFingerprint = p.Targets.Fingerprint()

	req := struct {
		KYC        Tri
		POC        Tri
		Reputation ReputationGate
		Fee        FeeGate
		RulesHash  string
		ScopeHash  string
	}{
		KYC:        p.KYC,
		POC:        p.POC,
		Reputation: p.Reputation,
		Fee:        p.Fee,
		RulesHash:  hashText(p.ProgramRules),
		ScopeHash:  hashText(p.ScopeNotes),
	}
	p.RequirementFingerprint = hashStruct("requirements", req)

	meta := struct {
		Name        string
		Slug        string
		Source      string
		State       ProgramState
		RawStatus   string
		RawState    string
		IsUnending  bool
		MinBounty   *float64
		MaxBounty   *float64
		Categories  Tags
		ProjectType Tags
		Tech        Tags
		CryptoKind  CryptoKind
		CryptoTrait Tags
	}{
		Name:        strings.TrimSpace(p.Name),
		Slug:        p.Slug,
		Source:      p.Source,
		State:       p.State,
		RawStatus:   p.RawStatus,
		RawState:    p.RawState,
		IsUnending:  p.IsUnending,
		MinBounty:   p.MinBountyUSD,
		MaxBounty:   p.MaxBountyUSD,
		Categories:  p.Categories.Clone(),
		ProjectType: p.ProjectTypes.Clone(),
		Tech:        p.Technologies.Clone(),
		CryptoKind:  p.CryptoKind,
		CryptoTrait: p.CryptoTraits.Clone(),
	}
	p.MetadataFingerprint = hashStruct("metadata", meta)
}

// Finalize normalizes derived fields and recomputes fingerprints.
// Normalization must always be the last step before persistence or comparison,
// so that fingerprints are computed over canonical values.
func (p *Program) Finalize() {
	p.Targets = append(Targets(nil), p.Targets...)
	sortTargets(p.Targets)

	p.Categories = NewTags(p.Categories...)
	p.ProjectTypes = NewTags(p.ProjectTypes...)
	p.Technologies = NewTags(p.Technologies...)
	p.Languages = NewTags(p.Languages...)
	p.CryptoTraits = NewTags(p.CryptoTraits...)
	p.SurfaceTags = NewTags(p.SurfaceTags...)
	p.CapabilityTags = NewTags(p.CapabilityTags...)
	p.ParseIssues = sortedUniqueStrings(p.ParseIssues)

	p.Name = strings.TrimSpace(p.Name)
	p.Slug = strings.TrimSpace(p.Slug)

	p.computeFingerprints()
}

// hashStruct returns a stable content hash over v, domain-separated by label.
func hashStruct(label string, v any) string {
	h := sha256.New()
	fmt.Fprintf(h, "hunter/%s/v1\n", label)
	if err := writeCanonical(h, v); err != nil {
		// A value that cannot be encoded would silently become an empty hash
		// and look like "unchanged". Make it loud instead.
		fmt.Fprintf(h, "unencodable:%v", err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashText returns a stable content hash over free text, used for long prose
// fields that participate in fingerprints but are never rendered into alerts.
func hashText(s string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", len(s))
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// ListingSignal is the listing-level observation recorded alongside a program.
//
// It is stored, rather than folded into the fingerprints, for two reasons: it
// answers "when was this program last refreshed from its detail page?" and it
// answers "did anything change in the listing since we last looked?", which is
// the cheap test that decides whether the expensive read is needed at all.
type ListingSignal struct {
	// UpdatedAt is the source's coarse last-modified marker.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	// Status and State preserve the source's lifecycle vocabulary.
	Status string `json:"status,omitempty"`
	State  string `json:"state,omitempty"`

	// RewardRaw is the displayed bounty string.
	RewardRaw string `json:"reward_raw,omitempty"`

	// RewardsPaidRaw is the displayed total paid out. A change here is a real
	// upstream change and does warrant a detail read.
	RewardsPaidRaw string `json:"rewards_paid_raw,omitempty"`

	// ActivityStatus is the source's human-facing activity label.
	ActivityStatus string `json:"activity_status,omitempty"`

	// Unending marks programs that never expire.
	Unending bool `json:"unending"`

	// Categories, ProjectTypes, and Technologies are the source's own
	// classification labels, which establish crypto character without a detail
	// read.
	Categories   []string `json:"categories,omitempty"`
	ProjectTypes []string `json:"project_types,omitempty"`
	Technologies []string `json:"technologies,omitempty"`

	// SubmissionCount and SubmissionCountKnown record the observed count. This
	// is excluded from the trigger comparison because it rises continuously.
	SubmissionCount      int  `json:"submission_count"`
	SubmissionCountKnown bool `json:"submission_count_known"`
}

// AsListing projects the signal into the comparable Listing shape.
func (s ListingSignal) AsListing() Listing {
	l := Listing{
		UpdatedAt:             s.UpdatedAt,
		Status:                s.Status,
		State:                 s.State,
		RewardRaw:             s.RewardRaw,
		RewardsPaidRaw:        s.RewardsPaidRaw,
		ActivityStatus:        s.ActivityStatus,
		Unending:              s.Unending,
		Categories:            s.Categories,
		ProjectTypes:          s.ProjectTypes,
		Technologies:          s.Technologies,
		SubmittedReportsKnown: s.SubmissionCountKnown,
	}
	if s.SubmissionCountKnown && s.SubmissionCount > 0 {
		n := s.SubmissionCount
		l.SubmittedReports = &n
	}
	return l
}

// Equal reports whether two listing observations match.
//
// Only fields that can change are compared; the observation timestamp is
// excluded so that a scan which observed nothing new is not treated as a change.
func (s ListingSignal) Equal(other ListingSignal) bool {
	l, o := s.AsListing(), other.AsListing()
	return l.Equal(o)
}

// Listing returns the program's recorded listing observation.
func (p Program) ListingSignal() ListingSignal { return p.Listing }

// ListingChangedSince reports whether the listing shows something that could
// warrant re-reading the detail page.
//
// It uses the trigger comparison rather than full equality, so that a rising
// submission count - which changes continuously on active programs - does not
// cause every program to be re-read on every scan.
func (p Program) ListingChangedSince(ref ProgramRef) bool {
	return ref.Listing.ChangedSince(p.Listing.AsListing())
}

// SubmissionSummary renders an observed submission count for display.
func (s ListingSignal) SubmissionSummary() string {
	if !s.SubmissionCountKnown {
		return "not published"
	}
	return itoa(s.SubmissionCount) + " submissions"
}

// Digest renders a listing signal as a stable string.
//
// It omits the observation timestamp, which changes on every scan and cannot
// affect a decision, so that comparing digests reports only genuine change.
func (s ListingSignal) Digest() string {
	var b strings.Builder
	if s.UpdatedAt != nil {
		b.WriteString(s.UpdatedAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("|")
	b.WriteString(s.Status)
	b.WriteString("|")
	b.WriteString(s.State)
	b.WriteString("|")
	b.WriteString(s.RewardRaw)
	b.WriteString("|")
	b.WriteString(s.RewardsPaidRaw)
	b.WriteString("|")
	b.WriteString(s.ActivityStatus)
	b.WriteString("|")
	b.WriteString(strconv.FormatBool(s.Unending))
	b.WriteString("|")
	b.WriteString(strings.Join(s.Categories, ","))
	b.WriteString("|")
	b.WriteString(strings.Join(s.ProjectTypes, ","))
	b.WriteString("|")
	b.WriteString(strings.Join(s.Technologies, ","))
	b.WriteString("|")
	b.WriteString(strconv.Itoa(s.SubmissionCount))
	return b.String()
}
