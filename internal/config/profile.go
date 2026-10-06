// Package config loads and validates the researcher profile.
//
// Every policy input the engine consults - reputation ceilings, fee ceilings,
// KYC tolerance, crypto mode, included and excluded target categories, program
// states, freshness thresholds, notification thresholds - is defined here and
// nowhere else. Changing what the system considers relevant must be a
// configuration edit, never a code change.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eadeshina/hunter/internal/domain"
	"gopkg.in/yaml.v3"
)

// AccessConfig describes what gates the researcher is willing to pass through.
type AccessConfig struct {
	// MaxReputationPoints is the highest reputation requirement the
	// researcher is willing to satisfy. Programs without a reputation gate
	// always pass. An omitted value defaults to 80; an explicit zero only
	// accepts programs that require no reputation.
	MaxReputationPoints int `yaml:"max_reputation_points"`

	maxReputationPointsSet bool `yaml:"-"`

	// MaxSubmissionFeeUSD is the highest submission fee the researcher will
	// pay. Programs with no fee always pass.
	MaxSubmissionFeeUSD float64 `yaml:"max_submission_fee_usd"`

	// KYCRequired declares whether the researcher is willing to perform KYC.
	// It is tri-state because "I do not know whether I would" is a real and
	// materially different answer from "no".
	KYCRequired domain.Tri `yaml:"kyc_required"`

	// POCRequired declares whether a proof-of-concept requirement is
	// acceptable. It mirrors kyc_required: "no" means a program that demands a
	// working exploit with the report is out of reach for this researcher.
	//
	// Unlike KYC, an unspecified stance defaults to acceptance. Providing a
	// proof of concept is normal bounty workflow rather than an identity or
	// monetary gate, so defaulting to refusal would silently narrow the channel
	// for the majority of the catalogue. An explicit "no" opts into refusal.
	POCRequired domain.Tri `yaml:"poc_required"`

	// AcceptUnknownAccessGates allows programs whose access facts could not
	// be determined. It defaults to false and must be enabled explicitly,
	// because a parser regression would otherwise silently widen results.
	AcceptUnknownAccessGates bool `yaml:"accept_unknown_access_gates"`

	// AcceptUnknownParseState allows programs the adapter could not fully
	// understand. Defaults to false.
	AcceptUnknownParseState bool `yaml:"accept_unknown_parse_state"`
}

// CryptoMode selects how crypto programs are filtered.
type CryptoMode string

const (
	// CryptoModeAuto applies the allow and exclude trait lists.
	CryptoModeAuto CryptoMode = "auto"
	// CryptoModeOff disables crypto filtering entirely.
	CryptoModeOff CryptoMode = "off"
	// CryptoModePlatformOnly admits only crypto programs with platform
	// character, without consulting the trait lists.
	CryptoModePlatformOnly CryptoMode = "platform_only"
	// CryptoModeOnly admits only crypto programs.
	CryptoModeOnly CryptoMode = "only"
)

// ParseCryptoMode validates a configured crypto mode.
func ParseCryptoMode(s string) (CryptoMode, error) {
	switch v := CryptoMode(strings.ToLower(strings.TrimSpace(s))); v {
	case CryptoModeAuto, CryptoModeOff, CryptoModePlatformOnly, CryptoModeOnly:
		return v, nil
	default:
		return "", fmt.Errorf("invalid crypto.mode %q: want auto|off|platform_only|only", s)
	}
}

// CryptoConfig controls how crypto programs are recognised and filtered.
type CryptoConfig struct {
	// Enabled turns crypto awareness on. When false, crypto traits are not
	// computed and crypto filtering is skipped.
	Enabled bool `yaml:"enabled"`

	// Mode selects the filtering strategy. Defaults to auto.
	Mode CryptoMode `yaml:"mode"`

	// Allowed lists crypto traits that make a program relevant.
	Allowed []string `yaml:"allowed"`

	// Excluded lists crypto traits that disqualify a program when they
	// dominate its classification.
	Excluded []string `yaml:"excluded"`

	// RequireAllowedTrait demands at least one Allowed trait before a crypto
	// program passes. Defaults to true when crypto filtering is enabled in auto
	// mode: admitting every crypto program is precisely the noise this system
	// exists to remove.
	RequireAllowedTrait bool `yaml:"require_allowed_trait"`

	requireAllowedTraitSet bool `yaml:"-"`

	// DominanceRatio is the fraction of crypto traits that must be excluded
	// for the excluded list to veto a program. A program that is both a crypto
	// exchange and has a smart-contract scope is not excluded, because the
	// platform surface dominates. Only when excluded traits meet or exceed
	// this share does the veto apply. Values are clamped to [0,1].
	DominanceRatio float64 `yaml:"dominance_ratio"`
}

// TargetDomainConfig selects which technical surfaces matter.
type TargetDomainConfig struct {
	// Included lists the surface tags a program must have at least one of.
	Included []string `yaml:"included"`

	// Excluded lists surface tags that disqualify a program. A program whose
	// scope consists only of excluded surfaces is rejected.
	Excluded []string `yaml:"excluded"`

	// ExcludeDominanceRatio is the fraction of a program's surfaces that must
	// be excluded for the veto to apply, preventing a single excluded asset in
	// an otherwise broad program from rejecting it.
	ExcludeDominanceRatio float64 `yaml:"exclude_dominance_ratio"`
}

// ProgramStateConfig lists the lifecycle states the researcher will act on.
type ProgramStateConfig struct {
	// Allowed lists acceptable states.
	Allowed []string `yaml:"allowed"`

	// AlertOnState lists states that trigger an alert even without other
	// changes, e.g. reactivation.
	AlertOnState []string `yaml:"alert_on_state"`
}

// FreshnessConfig tunes how age contributes to triage.
type FreshnessConfig struct {
	// FreshProgramWindow is the age below which a newly observed program is
	// considered brand new.
	FreshProgramWindow stringDuration `yaml:"fresh_program_window"`

	// FreshScopeWindow is the age below which a scope change is considered
	// recent.
	FreshScopeWindow stringDuration `yaml:"fresh_scope_window"`

	// StaleProgramAge is the age beyond which a program's base priority is
	// reduced.
	StaleProgramAge stringDuration `yaml:"stale_program_age"`
}

// NotificationConfig tunes what becomes an email.
type NotificationConfig struct {
	// Enabled turns delivery on. When false, alerts are still generated,
	// scored, and recorded, which is what makes dry runs safe.
	Enabled bool `yaml:"enabled"`

	// MinSeverity is the lowest change severity that may raise an alert.
	MinSeverity domain.Severity `yaml:"min_severity"`

	// RequireEligible alerts only for programs the profile accepts.
	RequireEligible bool `yaml:"require_eligible"`

	// AlertOnNewPrograms alerts when a qualifying program is seen for the
	// first time.
	AlertOnNewPrograms bool `yaml:"alert_on_new_programs"`

	// NewProgramWindow is the launch-recency gate.
	//
	// A program earns an alert only if the source reports it launched within
	// this window. A program that has been live for months is not an
	// opportunity, however well it matches the profile, so this is what keeps an
	// existing program off the channel entirely.
	//
	// A program whose launch date the source does not publish is never alerted
	// on, because "recently launched" cannot be established. The window is
	// sized to absorb a missed scan or a short outage: too tight and a single
	// failure silently loses an opportunity forever.
	NewProgramWindow stringDuration `yaml:"new_program_window"`

	// AlertOnMaterialChange alerts when a qualifying program's scope or
	// requirements change materially.
	AlertOnMaterialChange bool `yaml:"alert_on_material_change"`

	// AlertOnNewlyEligible alerts when a previously rejected program becomes
	// acceptable, such as a lowered reputation requirement.
	AlertOnNewlyEligible bool `yaml:"alert_on_newly_eligible"`

	// AlertOnScopeExpansion alerts when a qualifying program gains new
	// attack surface.
	AlertOnScopeExpansion bool `yaml:"alert_on_scope_expansion"`

	// MaxPerScan caps alerts raised by a single scan, protecting the channel
	// during a bulk re-import. Zero means no cap.
	MaxPerScan int `yaml:"max_per_scan"`

	// SubjectPrefix is prepended to every subject line.
	SubjectPrefix string `yaml:"subject_prefix"`

	// ChangeWindows sizes the recency window of each class of change.
	//
	// The launch window governs only whether a PROGRAM is new. These govern
	// whether a CHANGE is recent, which is a separate question with a separate
	// answer: a five-year-old program whose API scope grew nine minutes ago is a
	// fresh opportunity, and a launch-age gate cannot express that.
	ChangeWindows ChangeWindowsConfig `yaml:"change_windows"`
}

// ScanConfig tunes discovery and fetching.
type ScanConfig struct {
	// PerPage is the listing page size to request.
	PerPage int `yaml:"per_page"`

	// MaxPages bounds listing traversal. Zero means traverse to the end.
	MaxPages int `yaml:"max_pages"`

	// FetchDetails controls whether detail pages are fetched. Disabling it
	// makes discovery-only runs possible, at the cost of access-gate accuracy.
	FetchDetails bool `yaml:"fetch_details"`

	// DetailOnlySkipsUnchanged skips detail fetches for programs whose
	// listing observation is unchanged. This is the two-tier read: the listing
	// is swept every scan, and the detail page is read only when the cheap
	// check says something may have moved.
	DetailOnlySkipsUnchanged bool `yaml:"detail_only_skips_unchanged"`

	// FetchDetailsOnListingChange forces a detail read whenever the listing
	// observation differs from the stored one. Defaults to true; disabling it
	// means changes the listing does not expose are only caught by the periodic
	// refresh.
	FetchDetailsOnListingChange bool `yaml:"fetch_details_on_listing_change"`

	// detailChangeConfigured records whether the key was present, so that a
	// default of true is applied without overriding an explicit false.
	detailChangeConfigured bool `yaml:"-"`

	// DetailsRefreshInterval is the longest a detail record may go unrefreshed.
	// Zero disables the periodic refresh, which makes the listing the only
	// trigger and risks missing a change the listing does not expose.
	DetailsRefreshInterval stringDuration `yaml:"details_refresh_interval"`

	// RequestTimeout bounds a single HTTP request.
	RequestTimeout stringDuration `yaml:"request_timeout"`

	// MaxRetries bounds retries per request.
	MaxRetries int `yaml:"max_retries"`

	// RetryBaseDelay is the first backoff delay; subsequent delays double.
	RetryBaseDelay stringDuration `yaml:"retry_base_delay"`

	// MaxRetryDelay caps the exponential backoff.
	MaxRetryDelay stringDuration `yaml:"max_retry_delay"`

	// MinRequestInterval spaces out requests to one source.
	MinRequestInterval stringDuration `yaml:"min_request_interval"`

	// MaxConcurrent bounds concurrent detail fetches for one source.
	MaxConcurrent int `yaml:"max_concurrent"`

	ListingConcurrency int `yaml:"listing_concurrency"`

	// MaxCatchUpDetailFetchesPerScan caps the number of detail reads that are
	// performed to bring stale or never-fetched records up to date in a single
	// scan. It applies to:
	//   - initial bootstrap detail reads (records never fetched before),
	//   - periodic refreshes triggered by the elapsed-interval timer.
	// It does NOT limit detail reads triggered by:
	//   - listing changes (those are event-driven and must fire),
	//   - incomplete records (parse retries),
	//   - parse retries.
	// Zero disables the cap (unlimited catch-up), which reproduces the old
	// behaviour of a single massive catch-up sweep. A positive value spreads
	// large catch-up work across multiple scans.
	MaxCatchUpDetailFetchesPerScan int `yaml:"max_catch_up_detail_fetches_per_scan"`

	// UserAgent identifies the crawler. It must be truthful and stable.
	UserAgent string `yaml:"user_agent"`
}

// SourceConfig enables and configures individual adapters.
type SourceConfig struct {
	// Enabled turns the source on.
	Enabled bool `yaml:"enabled"`

	// BaseURL overrides the adapter's default endpoint.
	BaseURL string `yaml:"base_url"`

	// ListPath overrides the listing path.
	ListPath string `yaml:"list_path"`

	// DetailPathTemplate overrides the detail path template.
	DetailPathTemplate string `yaml:"detail_path_template"`
}

// Platforms is the source toggle map from the profile document. It is folded
// into Sources during validation so that callers have a single place to look.
type Platforms map[string]bool

// Profile is one researcher's hunting constraints.
type Profile struct {
	Name string `yaml:"name"`

	// Description documents the profile's intent, for humans.
	Description string `yaml:"description,omitempty"`

	Access        AccessConfig            `yaml:"access"`
	Crypto        CryptoConfig            `yaml:"crypto"`
	TargetDomains TargetDomainConfig      `yaml:"target_domains"`
	ProgramStates ProgramStateConfig      `yaml:"program_states"`
	Freshness     FreshnessConfig         `yaml:"freshness"`
	Coverage      CoverageConfig          `yaml:"coverage"`
	Notifications NotificationConfig      `yaml:"notifications"`
	Scan          ScanConfig              `yaml:"scan"`
	Platforms     Platforms               `yaml:"platforms"`
	Sources       map[string]SourceConfig `yaml:"sources"`

	// Parsed crypto trait sets, produced during validation.
	allowedCrypto  domain.CryptoTraits `yaml:"-"`
	excludedCrypto domain.CryptoTraits `yaml:"-"`

	// Parsed accessors, produced during validation.
	allowedStates []domain.ProgramState `yaml:"-"`
	alertOnStates []domain.ProgramState `yaml:"-"`
}

// String identifies the profile in logs and decisions.
func (p *Profile) String() string { return p.Name }

// CryptoModeOrDefault returns the crypto mode, defaulting to auto.
func (p *Profile) CryptoModeOrDefault() CryptoMode {
	if p.Crypto.Mode == "" {
		return CryptoModeAuto
	}
	return p.Crypto.Mode
}

// DominanceRatioOrDefault returns the crypto dominance ratio, clamped to [0,1].
func (p *Profile) CryptoDominanceRatio() float64 {
	r := p.Crypto.DominanceRatio
	if r <= 0 || r > 1 {
		return 0.5
	}
	return r
}

// TargetExcludeRatioOrDefault returns the target exclusion ratio, clamped.
func (p *Profile) TargetExcludeRatio() float64 {
	r := p.TargetDomains.ExcludeDominanceRatio
	if r <= 0 || r > 1 {
		return 0.5
	}
	return r
}

// FreshProgramWindowDuration returns the freshness window, defaulted.

// FreshScopeWindowDuration returns the scope freshness window, defaulted.

// Load reads, parses, and validates a profile from disk.
//
// Validation is strict and total: an unknown enum value is an error rather than
// a silently ignored key, because a typo in a policy file that quietly disables
// a filter would remove exactly the alerting the researcher depends on.
func Load(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return p, nil
}

// Parse decodes and validates a profile from raw YAML.
//
// Two document shapes are accepted: a bare profile, and a profile nested under
// a top-level "profile" key. Both exist because the nested form is the
// conventional shape for a named researcher profile and the flat form is
// convenient for a single-profile repository.
func Parse(raw []byte) (*Profile, error) {
	wrapped, err := hasProfileWrapper(raw)
	if err != nil {
		return nil, err
	}

	var p Profile
	// KnownFields makes unknown keys an error. Silently ignoring a misspelled
	// policy key is how a filter quietly stops working.
	var dec *yaml.Decoder
	if wrapped {
		dec = yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		var doc struct {
			Profile Profile `yaml:"profile"`
		}
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("parse profile: %w", err)
		}
		p = doc.Profile
	} else {
		dec = yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("parse profile: %w", err)
		}
	}

	// yaml's zero values do not distinguish an omitted integer/boolean from
	// an explicitly configured zero/false. Preserve presence for fields whose
	// documented defaults differ from those zero values.
	p.Access.maxReputationPointsSet = yamlPathPresent(raw, wrapped, "access", "max_reputation_points")
	p.Crypto.requireAllowedTraitSet = yamlPathPresent(raw, wrapped, "crypto", "require_allowed_trait")
	p.Scan.detailChangeConfigured = yamlPathPresent(raw, wrapped, "scan", "fetch_details_on_listing_change")

	if err := p.applyDefaultsAndValidate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// yamlPathPresent reports whether a nested key exists in the profile mapping.
// It is used only to distinguish an omitted zero-value option from an explicit
// zero or false; yaml.Decoder remains responsible for strict type and key
// validation.
func yamlPathPresent(raw []byte, wrapped bool, path ...string) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 {
		return false
	}
	node := doc.Content[0]
	if wrapped {
		path = append([]string{"profile"}, path...)
	}
	for _, part := range path {
		if node.Kind != yaml.MappingNode {
			return false
		}
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind == yaml.ScalarNode && key.Value == part {
				node = node.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// hasProfileWrapper reports whether the document nests the profile under a
// top-level "profile" key.
//
// Only the top level is inspected. A nested mapping node contributes its own
// key/value pairs to the parent's content slice, so scanning with a stride of
// two from the document root can wander into inner levels; the recursion below
// stays within the root mapping's own key positions.
func hasProfileWrapper(raw []byte) (bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("parse profile: %w", err)
	}
	if doc.Kind != yaml.DocumentNode {
		return false, fmt.Errorf("parse profile: expected a document")
	}
	if len(doc.Content) != 1 {
		return false, fmt.Errorf("parse profile: expected exactly one root node")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false, fmt.Errorf("parse profile: expected a mapping at the document root")
	}
	// At the root level the content slice is strictly alternating
	// key, value, key, value. Stop at the first non-scalar key, which marks
	// the end of the root's own keys.
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		if key.Kind != yaml.ScalarNode {
			break
		}
		if key.Value == "profile" {
			if root.Content[i+1].Kind != yaml.MappingNode {
				return false, fmt.Errorf("parse profile: \"profile\" must be a mapping")
			}
			return true, nil
		}
	}
	return false, nil
}

// applyDefaultsAndValidate finalizes derived configuration and reports every
// problem it finds, not just the first.
func (p *Profile) applyDefaultsAndValidate() error {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(p.Name) == "" {
		fail("profile.name is required")
	}

	// Access defaults. A zero-value reputation ceiling would reject every
	// program, which is never the intent of an omitted key. An explicit zero
	// remains valid and means that no reputation requirement is acceptable.
	if !p.Access.maxReputationPointsSet {
		p.Access.MaxReputationPoints = 80
	}
	if p.Access.MaxReputationPoints < 0 {
		fail("access.max_reputation_points must be >= 0")
	}
	if p.Access.MaxSubmissionFeeUSD < 0 {
		fail("access.max_submission_fee_usd must be >= 0")
	}
	if !p.Access.KYCRequired.Known() {
		// An unspecified KYC policy is treated as "unwilling", which is the
		// safe direction: it can only narrow results, never widen them.
		p.Access.KYCRequired = domain.TriNo
	}
	if !p.Access.POCRequired.Known() {
		// An unspecified PoC stance defaults to acceptance, which preserves the
		// behavior of profiles written before the setting existed. Refusal must
		// be explicit, because most of the catalogue requires a proof of
		// concept and a silent default-refusal would narrow the channel
		// without the profile saying so.
		p.Access.POCRequired = domain.TriYes
	}

	// Crypto.
	if p.Crypto.Mode == "" {
		p.Crypto.Mode = CryptoModeAuto
	}
	if p.Crypto.Enabled && p.Crypto.Mode == CryptoModeAuto && !p.Crypto.requireAllowedTraitSet {
		p.Crypto.RequireAllowedTrait = true
	}
	if _, err := ParseCryptoMode(string(p.Crypto.Mode)); err != nil {
		fail("%v", err)
	}
	allowed, err := parseTraits(p.Crypto.Allowed)
	if err != nil {
		fail("crypto.allowed: %v", err)
	}
	excluded, err := parseTraits(p.Crypto.Excluded)
	if err != nil {
		fail("crypto.excluded: %v", err)
	}
	p.allowedCrypto, p.excludedCrypto = allowed, excluded
	if p.Crypto.Enabled && p.Crypto.Mode == CryptoModeAuto && p.Crypto.RequireAllowedTrait && len(allowed) == 0 {
		fail("crypto.require_allowed_trait is true but crypto.allowed is empty")
	}
	if p.Crypto.Enabled && p.Crypto.Mode == CryptoModeAuto && !p.Crypto.RequireAllowedTrait && len(allowed) > 0 {
		// With an allow list present but the requirement disabled, the list
		// would have no effect. Surfacing this prevents a profile that looks
		// filtered but is not.
		fail("crypto.allow list is set but crypto.require_allowed_trait is false: the allow list would have no effect")
	}
	if p.Crypto.Mode != CryptoModeAuto && len(allowed) > 0 {
		p.Crypto.RequireAllowedTrait = false
	}
	if p.Crypto.DominanceRatio < 0 || p.Crypto.DominanceRatio > 1 {
		fail("crypto.dominance_ratio must be between 0 and 1")
	}

	// Target domains.
	for _, d := range p.TargetDomains.Included {
		if strings.TrimSpace(d) == "" {
			fail("target_domains.included contains an empty entry")
		}
	}
	for _, d := range p.TargetDomains.Excluded {
		for _, inc := range p.TargetDomains.Included {
			if strings.EqualFold(strings.TrimSpace(d), strings.TrimSpace(inc)) {
				fail("target_domains: %q appears in both included and excluded", d)
			}
		}
	}
	if p.TargetDomains.ExcludeDominanceRatio < 0 || p.TargetDomains.ExcludeDominanceRatio > 1 {
		fail("target_domains.exclude_dominance_ratio must be between 0 and 1")
	}

	// Program states.
	allowedStates, err := parseStates(p.ProgramStates.Allowed)
	if err != nil {
		fail("program_states.allowed: %v", err)
	}
	alertStates, err := parseStates(p.ProgramStates.AlertOnState)
	if err != nil {
		fail("program_states.alert_on_state: %v", err)
	}
	p.allowedStates, p.alertOnStates = allowedStates, alertStates
	if len(p.allowedStates) == 0 {
		p.allowedStates = []domain.ProgramState{domain.StateLive, domain.StateNew}
	}

	// Freshness.
	for _, d := range []struct {
		name string
		val  stringDuration
	}{
		{"freshness.fresh_program_window", p.Freshness.FreshProgramWindow},
		{"freshness.fresh_scope_window", p.Freshness.FreshScopeWindow},
		{"freshness.stale_program_age", p.Freshness.StaleProgramAge},
	} {
		if d.val < 0 {
			fail("%s must be >= 0", d.name)
		}
	}

	// Notifications.
	if p.Notifications.MinSeverity == "" {
		p.Notifications.MinSeverity = domain.SeverityMedium
	}
	switch p.Notifications.MinSeverity {
	case domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh:
	default:
		fail("notifications.min_severity %q must be low|medium|high", p.Notifications.MinSeverity)
	}
	if p.Notifications.MaxPerScan < 0 {
		fail("notifications.max_per_scan must be >= 0")
	}
	if p.Notifications.NewProgramWindow < 0 {
		fail("notifications.new_program_window must be >= 0")
	}
	if p.Notifications.NewProgramWindow == 0 {
		fail("notifications.new_program_window must be set: without it a program that " +
			"launched years ago would be reported as new")
	}
	if !p.Notifications.AlertOnNewPrograms && !p.Notifications.AlertOnMaterialChange &&
		!p.Notifications.AlertOnNewlyEligible && !p.Notifications.AlertOnScopeExpansion {
		fail("notifications: at least one alert_on_* trigger must be enabled")
	}

	// Coverage. A ratio outside [0,1] is rejected rather than clamped: a
	// misconfigured alarm that silently widens or narrows the trust threshold is
	// worse than one that refuses to load.
	if p.Coverage.MinRatio < 0 || p.Coverage.MinRatio > 1 {
		fail("coverage.min_ratio must be between 0 and 1")
	}
	if p.Coverage.GraceSweeps < 0 {
		fail("coverage.grace_sweeps must be >= 0")
	}

	// Change windows are resolved here so that a bad key or a missing default is
	// reported at load time rather than at the moment a change fires.
	var windowErrs []string
	p.Notifications.ChangeWindows.resolve(&windowErrs)
	for _, e := range windowErrs {
		fail("%s", e)
	}
	if p.Notifications.ChangeWindows.BundleWindow < 0 {
		fail("notifications.change_windows.bundle_window must be >= 0")
	}
	if p.Notifications.ChangeWindows.MaxAge < 0 {
		fail("notifications.change_windows.max_age must be >= 0")
	}
	if p.Notifications.ChangeWindows.MaxPostChangeSubmissions < 0 {
		fail("notifications.change_windows.max_post_change_submissions must be >= 0")
	}

	// Scan.
	if p.Scan.PerPage <= 0 {
		p.Scan.PerPage = 10
	}
	if p.Scan.MaxPages < 0 {
		fail("scan.max_pages must be >= 0")
	}
	if p.Scan.MaxRetries < 0 {
		fail("scan.max_retries must be >= 0")
	}
	if p.Scan.MaxConcurrent < 0 {
		fail("scan.max_concurrent must be >= 0")
	}
	if p.Scan.MaxConcurrent <= 0 {
		p.Scan.MaxConcurrent = 2
	}
	if p.Scan.ListingConcurrency < 0 {
		fail("scan.listing_concurrency must be >= 0")
	}
	if p.Scan.MaxCatchUpDetailFetchesPerScan < 0 {
		fail("scan.max_catch_up_detail_fetches_per_scan must be >= 0")
	}
	// The listing-change trigger defaults to on. Leaving it off would mean the
	// cheap tier notices that nothing moved but never re-reads anything that did,
	// which would silently disable change detection altogether. A profile that
	// genuinely wants the cheap tier alone must say so explicitly.
	if !p.Scan.detailChangeConfigured {
		p.Scan.FetchDetailsOnListingChange = true
	}
	if p.Scan.RequestTimeout == 0 {
		p.Scan.RequestTimeout = stringDuration(defaultTimeout)
	}
	if p.Scan.RetryBaseDelay == 0 {
		p.Scan.RetryBaseDelay = stringDuration(defaultRetryBase)
	}
	if p.Scan.MaxRetryDelay == 0 {
		p.Scan.MaxRetryDelay = stringDuration(defaultMaxRetryDelay)
	}
	if p.Scan.UserAgent == "" {
		p.Scan.UserAgent = defaultUserAgent
	}
	if p.Scan.MinRequestInterval == 0 {
		p.Scan.MinRequestInterval = stringDuration(defaultMinInterval)
	}

	// Sources. The platforms map is an alternative spelling of the same
	// toggle, so both are merged rather than requiring the author to pick one.
	// The sources map must exist before anything is merged into it. Writing to a
	// nil map panics, so a profile that declared only "platforms" would otherwise
	// crash during validation.
	if p.Sources == nil {
		p.Sources = map[string]SourceConfig{}
	}
	for name, on := range p.Platforms {
		if strings.TrimSpace(name) == "" {
			fail("platforms contains an empty source name")
			continue
		}
		cfg := p.Sources[name]
		cfg.Enabled = on
		p.Sources[name] = cfg
	}
	if len(p.Sources) == 0 {
		p.Sources = map[string]SourceConfig{"hackenproof": {Enabled: true}}
	}
	for _, name := range sortedKeys(p.Sources) {
		if strings.TrimSpace(name) == "" {
			fail("sources contains an empty source name")
		}
	}
	if len(p.EnabledSources()) == 0 {
		fail("no sources are enabled: at least one source must be turned on")
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("invalid profile:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// EnabledSources returns the source names enabled by the profile, sorted.
func (p *Profile) EnabledSources() []string {
	out := make([]string, 0, len(p.Sources))
	for name, cfg := range p.Sources {
		if cfg.Enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AllowedCryptoTraits returns the parsed crypto allow list.
func (p *Profile) AllowedCryptoTraits() domain.CryptoTraits { return p.allowedCrypto }

// ExcludedCryptoTraits returns the parsed crypto exclude list.
func (p *Profile) ExcludedCryptoTraits() domain.CryptoTraits { return p.excludedCrypto }

func (p *Profile) allowedCryptoFor() domain.CryptoTraits { return p.allowedCrypto }

func (p *Profile) excludedCryptoFor() domain.CryptoTraits { return p.excludedCrypto }

// SourceConfigFor returns the configuration for a named source.
func (p *Profile) SourceConfigFor(name string) SourceConfig { return p.Sources[name] }

func parseTraits(names []string) (domain.CryptoTraits, error) {
	out := make(domain.CryptoTraits, 0, len(names))
	for _, n := range names {
		t, ok := domain.ParseCryptoTrait(n)
		if !ok {
			return nil, fmt.Errorf("unknown crypto trait %q: valid values are %s", n, joinTraits())
		}
		out = append(out, t)
	}
	return out, nil
}

func parseStates(names []string) ([]domain.ProgramState, error) {
	out := make([]domain.ProgramState, 0, len(names))
	for _, n := range names {
		s, ok := domain.ParseProgramState(n)
		if !ok {
			return nil, fmt.Errorf("unknown program state %q", n)
		}
		out = append(out, s)
	}
	return out, nil
}

func joinTraits() string {
	all := domain.AllCryptoTraits()
	parts := make([]string, 0, len(all))
	for _, t := range all {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]SourceConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scanHasKey reports whether a key appears anywhere in a document.
//
// It is used to distinguish "the author set this to false" from "the author did
// not mention it", which matters only for the one option whose default is true.
// A crude scan is sufficient and preferable to a full decode of the node tree
// for a single boolean.
func scanHasKey(raw []byte, key string) bool {
	needle := key + ":"
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}
