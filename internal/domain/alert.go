package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// AlertKind classifies why an alert was raised.
type AlertKind string

const (
	// AlertNewQualifying is a qualifying program seen for the first time.
	AlertNewQualifying AlertKind = "NEW_QUALIFYING"
	// AlertMaterialChange is a qualifying program whose attack surface or
	// requirements changed materially.
	AlertMaterialChange AlertKind = "MATERIAL_CHANGE"
	// AlertNewlyEligible is a previously rejected program that now qualifies.
	AlertNewlyEligible AlertKind = "NEWLY_ELIGIBLE"
	// AlertScopeExpansion is a qualifying program that gained new surface.
	AlertScopeExpansion AlertKind = "SCOPE_EXPANSION"
)

// Alert is a single notification, fully rendered and independently
// deduplicable.
//
// An Alert is self-contained: the notifier receives everything it needs and
// never has to consult state to format a message. That keeps delivery idempotent
// under workflow retry.
type Alert struct {
	// Fingerprint uniquely identifies the alerting condition. Two scans that
	// observe the same condition produce the same fingerprint, which is what
	// suppresses duplicate mail.
	Fingerprint string `json:"fingerprint"`

	Kind AlertKind `json:"kind"`

	ProgramID string  `json:"program_id"`
	Program   Program `json:"program"`

	// Changes is the set that triggered the alert.
	Changes ChangeSet `json:"changes,omitempty"`

	// Decision is the eligibility decision at alert time, including reasons.
	Decision EligibilityDecision `json:"decision"`

	// Triage holds the exposed scoring components.
	Triage Triage `json:"triage"`

	// Freshness holds the independent age signals.
	Freshness Freshness `json:"freshness"`

	// DetectedAgeshows how long ago the opportunity was detected, as
	// observed at alert time.
	DetectedAt time.Time `json:"detected_at"`

	// LaunchAge is how long ago the source reported the program launching, and
	// LaunchKnown records whether it reported one at all. Both travel with the
	// alert so the message can state how new the program is without recomputing
	// it, and so an alert can never be rendered without the evidence for its own
	// headline claim.
	LaunchAge   time.Duration `json:"launch_age,omitempty"`
	LaunchKnown bool          `json:"launch_known"`

	// ScanID ties the alert back to the scan that produced it.
	ScanID string `json:"scan_id"`

	// HTMLBody is the styled alternative to Body. Both are rendered from the
	// same state, so the two can never disagree, and the plain-text part
	// remains a complete fallback for clients that will not render HTML.
	HTMLBody string `json:"-"`

	// Subject and Body are pre-rendered so that delivery is deterministic and
	// testable without a mail transport.
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// ComputeFingerprint derives the deterministic alert fingerprint.
//
// Only conditions that should re-trigger an alert participate. Timestamps that
// change on every scan (last seen, observation time) are excluded, otherwise
// every scan would look like a new condition and the channel would flood.
func ComputeFingerprint(kind AlertKind, programID string, changes ChangeSet, decision EligibilityDecision, extra ...string) string {
	h := sha256.New()
	fmt.Fprintf(h, "hunter/alert/v1\nkind=%s\nprogram=%s\n", kind, programID)
	// A newly eligible program should re-alert even if its scope is unchanged,
	// because the reason the researcher should act is new. Including the
	// eligibility transition in the fingerprint expresses that.
	if kind == AlertNewlyEligible {
		fmt.Fprintf(h, "newly_eligible=1\n")
	}
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.Severity.AtLeast(SeverityMedium) {
			parts = append(parts, string(c.Kind)+"|"+c.Field+"|"+c.After)
		}
	}
	for _, p := range parts {
		fmt.Fprintf(h, "change=%s\n", p)
	}
	for _, e := range extra {
		fmt.Fprintf(h, "extra=%s\n", e)
	}
	// The decision's pass set is part of identity only when it changed; the
	// full reason list is too volatile to include.
	fmt.Fprintf(h, "eligible=%t\n", decision.Eligible)
	return hex.EncodeToString(h.Sum(nil))
}

// ShortFingerprint returns a human-usable identifier for logs.
func (a Alert) ShortFingerprint() string {
	if len(a.Fingerprint) <= 12 {
		return a.Fingerprint
	}
	return a.Fingerprint[:12]
}

// AlertRecord is the persisted delivery record for one alert.
//
// Recording intent before delivery and the outcome afterwards is what makes
// retries safe: a workflow that dies between send and record will re-attempt,
// and the idempotency key prevents a second copy of the same message.
type AlertRecord struct {
	Fingerprint string    `json:"fingerprint"`
	Kind        AlertKind `json:"kind"`
	ProgramID   string    `json:"program_id"`
	ScanID      string    `json:"scan_id"`
	CreatedAt   time.Time `json:"created_at"`

	Subject string `json:"subject"`

	// Body is stored alongside the subject so an alert that was generated but
	// not delivered can be retried verbatim. Redelivery must not depend on
	// regenerating the condition, because by then it may no longer be new - a
	// previewed alert would otherwise sit pending forever.
	Body string `json:"body,omitempty"`

	// Attempts counts delivery attempts, including failures.
	Attempts int `json:"attempts"`

	// Delivered is true once a notifier confirmed the send.
	Delivered bool `json:"delivered"`

	// LastAttemptAt and LastError record the most recent attempt.
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`

	// DeliveredAt records successful delivery.
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
}

// Fingerprint computes the alert fingerprint.
//
// It is a method on AlertRecord so that the pipeline and any future notifier
// derive identity the same way.
func (a Alert) FingerprintKey() string { return a.Fingerprint }

// Observation records that a program was seen during a scan, together with the
// decision and reasoning at that moment.
//
// Storing the reasoning for rejected programs is what allows `hunter explain`
// and future profile tuning to answer "why did I never hear about this one?",
// which is otherwise impossible to reconstruct after the fact.
type Observation struct {
	ScanID     string `json:"scan_id"`
	ProgramID  string `json:"program_id"`
	ObservedAt string `json:"observed_at"`

	Eligible bool     `json:"eligible"`
	Reasons  []string `json:"reasons,omitempty"`

	ScopeFingerprint       string `json:"scope_fingerprint,omitempty"`
	RequirementFingerprint string `json:"requirement_fingerprint,omitempty"`
	MetadataFingerprint    string `json:"metadata_fingerprint,omitempty"`

	// ChangesKinds lists what changed in this observation.
	ChangesKinds []string `json:"changes,omitempty"`

	// AlertFingerprint links to the alert raised, if any.
	AlertFingerprint string `json:"alert_fingerprint,omitempty"`
}

// Freshness holds independent age signals.
//
// Keeping these separate is the point: a program launched three years ago whose
// API scope was expanded six minutes ago is a very different opportunity from a
// program launched six minutes ago, and collapsing both into a single "age"
// number would hide the second one.
type Freshness struct {
	// ProgramAge is the time since launch, when the source states a launch date.
	ProgramAge time.Duration `json:"program_age,omitempty"`

	// ProgramAgeBasis explains which timestamp ProgramAge used.
	ProgramAgeBasis AgeBasis `json:"program_age_basis,omitempty"`

	// FirstSeenAge is the time since this system first observed the program.
	FirstSeenAge time.Duration `json:"first_seen_age,omitempty"`

	// SourceUpdateAge is the time since the source's own last-modified marker.
	SourceUpdateAge time.Duration `json:"source_update_age,omitempty"`

	// ScopeChangeAge is the time since the in-scope asset set last changed.
	ScopeChangeAge time.Duration `json:"scope_change_age,omitempty"`

	// RequirementChangeAge is the time since access requirements last changed.
	RequirementChangeAge time.Duration `json:"requirement_change_age,omitempty"`
}

// AgeStrings renders each signal for display, omitting signals that are not
// available rather than printing zero.
func (f Freshness) AgeStrings() []string {
	out := make([]string, 0, 6)
	add := func(label string, d time.Duration, known bool) {
		if known {
			out = append(out, label+": "+HumanizeDuration(d))
		}
	}
	add("program age", f.ProgramAge, f.ProgramAgeBasis != AgeUnknown && f.ProgramAge > 0)
	add("first seen", f.FirstSeenAge, f.FirstSeenAge > 0)
	add("source updated", f.SourceUpdateAge, f.SourceUpdateAge > 0)
	add("scope changed", f.ScopeChangeAge, f.ScopeChangeAge > 0)
	add("requirements changed", f.RequirementChangeAge, f.RequirementChangeAge > 0)
	return out
}

// HumanizeDuration renders a duration in the compact form used in alerts.
func HumanizeDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1h ago"
		}
		return fmt.Sprintf("%dh ago", h)
	case d < 365*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1d ago"
		}
		if days < 30 {
			return fmt.Sprintf("%dd ago", days)
		}
		months := days / 30
		return fmt.Sprintf("%dmo ago", months)
	default:
		years := int(d.Hours()/24) / 365
		if years == 1 {
			return "1y ago"
		}
		return fmt.Sprintf("%dy ago", years)
	}
}

// JoinNonEmpty joins non-empty strings with sep.
func JoinNonEmpty(sep string, parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}
