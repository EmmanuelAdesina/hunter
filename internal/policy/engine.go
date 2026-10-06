// Package policy decides whether a program matches a researcher's profile.
//
// The engine is a pure function of (program, profile). It performs no I/O, keeps
// no state, and returns the same decision for the same inputs, which is what
// makes an eligibility claim reproducible after the fact.
//
// Two properties are load-bearing:
//
//   - Every requirement is evaluated independently and recorded. A decision is
//     always reconstructible from its checks, so "why was this rejected?" always
//     has an answer.
//   - An unknown fact blocks approval unless the profile explicitly opts in.
//     Parsing uncertainty must never silently become eligibility.
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// Check identifiers. They are stable strings because they appear in stored
// decisions, log lines, and CLI output that a human may compare across runs.
const (
	CheckReputation      = "access.reputation"
	CheckSubmissionFee   = "access.submission_fee"
	CheckKYC             = "access.kyc"
	CheckPOC             = "access.poc"
	CheckState           = "program.state"
	CheckAcceptsReports  = "program.accepts_reports"
	CheckParseTrust      = "data.parse_trust"
	CheckSurfaces        = "scope.surfaces"
	CheckSurfaceExcluded = "scope.excluded_dominant"
	CheckCryptoIdentity  = "crypto.identity"
	CheckCryptoAllowed   = "crypto.allowed_trait"
	CheckCryptoExcluded  = "crypto.excluded_dominant"
)

// Engine evaluates programs against a profile.
type Engine struct {
	profile *config.Profile
	now     func() time.Time
}

// New builds an engine for a profile.
func New(p *config.Profile, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{profile: p, now: now}
}

// Profile returns the engine's profile.
func (e *Engine) Profile() *config.Profile { return e.profile }

// Evaluate produces a structured decision for one program.
func (e *Engine) Evaluate(p domain.Program) domain.EligibilityDecision {
	b := newBuilder(e.profile.Name, e.now().UTC().Format(time.RFC3339))

	e.checkTrust(b, p)
	e.checkReputation(b, p)
	e.checkFee(b, p)
	e.checkKYC(b, p)
	e.checkPOC(b, p)
	e.checkState(b, p)
	e.checkAcceptsReports(b, p)
	e.checkSurfaces(b, p)
	e.checkCrypto(b, p)

	return b.build(e.profile.Name, e.now().UTC().Format(time.RFC3339))
}

// checkTrust decides whether the record can be acted on at all.
//
// This runs first because it gates the meaning of everything else: a record the
// adapter could not read has no access facts, and treating those as absent would
// approve the program.
func (e *Engine) checkTrust(b *builder, p domain.Program) {
	if p.ParseConfidence == domain.ConfidenceLow {
		detail := "the source record could not be fully understood"
		if len(p.ParseIssues) > 0 {
			detail += ": " + strings.Join(p.ParseIssues, "; ")
		}
		if e.profile.Access.AcceptUnknownParseState {
			b.pass(CheckParseTrust, "program data must be fully understood",
				"low parse confidence accepted by profile", "accept_unknown_parse_state=true")
			return
		}
		b.unknown(CheckParseTrust, "program data must be fully understood", detail)
		return
	}
	if p.ParseConfidence == domain.ConfidencePartial {
		// A partially understood record is not a fully understood one, and the
		// profile's default refuses to auto-accept anything the adapter could
		// not fully understand. The access facts that are present may look
		// complete while the surrounding structure was not, which is exactly
		// the shape a parser regression takes.
		if e.profile.Access.AcceptUnknownParseState {
			b.pass(CheckParseTrust, "program data must be fully understood",
				"partially understood record accepted by profile", "accept_unknown_parse_state=true")
			return
		}
		detail := "the source record was only partially understood"
		if len(p.ParseIssues) > 0 {
			detail += ": " + strings.Join(p.ParseIssues, "; ")
		}
		b.unknown(CheckParseTrust, "program data must be fully understood", detail)
		return
	}
	b.pass(CheckParseTrust, "program data must be fully understood",
		"fully understood", "access facts present")
}

// checkReputation enforces the reputation ceiling.
func (e *Engine) checkReputation(b *builder, p domain.Program) {
	max := e.profile.Access.MaxReputationPoints

	switch p.Reputation.Present {
	case domain.TriNo:
		b.pass(CheckReputation, "reputation requirement must be within reach",
			"no reputation required", "<= "+itoa(max)+" reputation points")
	case domain.TriYes:
		observed := itoa(p.Reputation.Points) + " reputation points"
		expected := "within the configured maximum of " + itoa(max)
		if p.Reputation.Points <= max {
			b.pass(CheckReputation, "reputation requirement must be within reach", observed, expected)
		} else {
			b.fail(CheckReputation, "reputation requirement must be within reach", observed, expected, "")
		}
	default:
		if e.profile.Access.AcceptUnknownAccessGates {
			b.pass(CheckReputation, "reputation requirement must be within reach",
				"unknown accepted by profile", "accept_unknown_access_gates=true")
			return
		}
		b.unknown(CheckReputation, "reputation requirement must be within reach",
			"the source did not state a reputation requirement that could be read")
	}
}

// checkFee enforces the submission fee ceiling.
//
// The platform expresses fees in the account's own currency, so a non-zero fee
// cannot be converted to a comparable amount. That is reported as unknown
// rather than as zero, because assuming "free" when a fee exists would approve
// an unreachable program.
func (e *Engine) checkFee(b *builder, p domain.Program) {
	maxUSD := e.profile.Access.MaxSubmissionFeeUSD
	expected := "within the configured maximum of " + usd(maxUSD)

	switch p.Fee.Present {
	case domain.TriNo:
		b.pass(CheckSubmissionFee, "submission fee must be affordable", "no submission fee", "")
	case domain.TriYes:
		observed := usd(p.Fee.USD)
		if p.Fee.USD <= maxUSD {
			b.pass(CheckSubmissionFee, "submission fee must be affordable", observed, expected)
		} else {
			b.fail(CheckSubmissionFee, "submission fee must be affordable", observed, expected, "")
		}
	default:
		if e.profile.Access.AcceptUnknownAccessGates {
			b.pass(CheckSubmissionFee, "submission fee must be affordable",
				"unknown accepted by profile", "accept_unknown_access_gates=true")
			return
		}
		b.unknown(CheckSubmissionFee, "submission fee must be affordable",
			"the platform states fees in the account currency, which cannot be compared to a USD ceiling")
	}
}

// checkKYC enforces the identity-verification policy.
func (e *Engine) checkKYC(b *builder, p domain.Program) {
	willing := e.profile.Access.KYCRequired

	if !p.KYC.Known() {
		if e.profile.Access.AcceptUnknownAccessGates {
			b.pass(CheckKYC, "KYC requirement must be compatible", "unknown accepted by profile", "accept_unknown_access_gates=true")
			return
		}
		b.unknown(CheckKYC, "KYC requirement must be compatible",
			"the source did not state whether identity verification is required")
		return
	}

	if !willing.Known() {
		b.unknown(CheckKYC, "KYC requirement must be compatible",
			"the profile does not state a KYC stance")
		return
	}

	switch {
	case p.KYC.No() && !willing.Yes():
		b.pass(CheckKYC, "KYC requirement must be compatible", "KYC is not required", "profile does not require KYC")
	case p.KYC.Yes() && willing.Yes():
		b.pass(CheckKYC, "KYC requirement must be compatible", "KYC is required and accepted by the profile", "")
	case p.KYC.Yes():
		b.fail(CheckKYC, "KYC requirement must be compatible", "KYC is required", "the profile does not accept KYC",
			"the program is unreachable without identity verification")
	default:
		b.pass(CheckKYC, "KYC requirement must be compatible", "KYC is not required", "profile does not require KYC")
	}
}

// checkPOC enforces the proof-of-concept policy, mirroring checkKYC.
//
// A PoC requirement is an access gate in the same structural sense as KYC: the
// program demands something beyond the report itself. It differs in default
// posture only — acceptance unless the profile explicitly refuses — because
// providing a proof of concept is normal bounty workflow.
func (e *Engine) checkPOC(b *builder, p domain.Program) {
	willing := e.profile.Access.POCRequired

	if !p.POC.Known() {
		if e.profile.Access.AcceptUnknownAccessGates {
			b.pass(CheckPOC, "PoC requirement must be compatible", "unknown accepted by profile", "accept_unknown_access_gates=true")
			return
		}
		b.unknown(CheckPOC, "PoC requirement must be compatible",
			"the source did not state whether a proof of concept is required")
		return
	}

	if !willing.Known() {
		b.unknown(CheckPOC, "PoC requirement must be compatible",
			"the profile does not state a PoC stance")
		return
	}

	switch {
	case p.POC.No() && !willing.Yes():
		b.pass(CheckPOC, "PoC requirement must be compatible", "PoC is not required", "profile does not require a PoC")
	case p.POC.Yes() && willing.Yes():
		b.pass(CheckPOC, "PoC requirement must be compatible", "PoC is required and accepted by the profile", "")
	case p.POC.Yes():
		b.fail(CheckPOC, "PoC requirement must be compatible", "PoC is required", "the profile does not accept a PoC requirement",
			"the program is unreachable without a working exploit")
	default:
		b.pass(CheckPOC, "PoC requirement must be compatible", "PoC is not required", "profile does not require a PoC")
	}
}

// checkState enforces the accepted lifecycle states.
func (e *Engine) checkState(b *builder, p domain.Program) {
	if p.State == domain.StateUnknown {
		b.unknown(CheckState, "program state must be acceptable",
			"the source did not expose a recognizable lifecycle state")
		return
	}

	allowed := e.profile.AllowedStates()
	for _, s := range allowed {
		if s == p.State {
			b.pass(CheckState, "program state must be acceptable",
				"program state is "+string(p.State), "one of: "+stateList(allowed))
			return
		}
	}
	b.fail(CheckState, "program state must be acceptable",
		"program state is "+string(p.State), "one of: "+stateList(allowed), "")
}

// checkAcceptsReports rejects programs that are not currently accepting work.
func (e *Engine) checkAcceptsReports(b *builder, p domain.Program) {
	if p.AcceptsReports() {
		b.pass(CheckAcceptsReports, "program must currently accept reports",
			"program accepts reports", "live or new")
		return
	}
	b.fail(CheckAcceptsReports, "program must currently accept reports",
		"program does not accept reports", "live or new", "")
}

// checkSurfaces enforces the technical-surface requirement.
func (e *Engine) checkSurfaces(b *builder, p domain.Program) {
	included := domain.NewTags(e.profile.TargetDomains.Included...)
	if len(included) == 0 {
		b.skip(CheckSurfaces, "program must expose a target domain of interest",
			"the profile does not restrict target domains")
	} else {
		if p.SurfaceTags.HasAny(included...) {
			b.pass(CheckSurfaces, "program must expose a target domain of interest",
				"exposes "+p.SurfaceTags.Intersect(included).Join(), "one of "+included.Join())
		} else {
			observed := "exposes " + describeTags(p.SurfaceTags)
			if len(p.SurfaceTags) == 0 {
				observed = "exposes no recognizable target surface"
			}
			b.fail(CheckSurfaces, "program must expose a target domain of interest",
				observed, "one of: "+included.Join(), "")
		}
	}

	excluded := domain.NewTags(e.profile.TargetDomains.Excluded...)
	if len(excluded) == 0 {
		b.skip(CheckSurfaceExcluded, "excluded target domains must not dominate",
			"the profile excludes no target domains")
		return
	}

	hits := p.SurfaceTags.Intersect(excluded)
	if len(hits) == 0 {
		b.pass(CheckSurfaceExcluded, "excluded target domains must not dominate",
			"no excluded surfaces present", "excluded: "+excluded.Join())
		return
	}
	ratio := float64(len(hits)) / float64(len(p.SurfaceTags))
	if ratio >= e.profile.TargetExcludeRatio() {
		b.fail(CheckSurfaceExcluded, "excluded target domains must not dominate",
			"excluded surfaces are "+hits.Join(), "less than "+pct(e.profile.TargetExcludeRatio())+" of scope", "")
		return
	}
	b.pass(CheckSurfaceExcluded, "excluded target domains must not dominate",
		"excluded surfaces are a minority of scope", "less than "+pct(e.profile.TargetExcludeRatio())+" of scope")
}

// checkCrypto distinguishes crypto businesses from protocol research.
//
// The distinction the mandate turns on is that a crypto exchange with a web and
// API surface is ordinary software work, while a smart-contract or consensus
// program is not. Both cases are handled here rather than by the profile
// enumerating exclusions alone, so that a mixed program is judged on its
// dominant character instead of being either included or excluded arbitrarily.
func (e *Engine) checkCrypto(b *builder, p domain.Program) {
	cfg := e.profile.Crypto
	mode := e.profile.CryptoModeOrDefault()

	if !cfg.Enabled || mode == config.CryptoModeOff {
		b.skip(CheckCryptoIdentity, "crypto classification must be compatible",
			"crypto filtering is disabled")
		return
	}

	switch p.CryptoKind {
	case domain.CryptoNotCrypto:
		b.skip(CheckCryptoIdentity, "crypto classification must be compatible",
			"not a crypto program")
		return
	case domain.CryptoUnknown:
		if mode == config.CryptoModeOnly || mode == config.CryptoModeAuto {
			b.unknown(CheckCryptoIdentity, "crypto classification must be compatible",
				"labelled as crypto but no crypto surface could be confirmed")
			return
		}
		b.skip(CheckCryptoIdentity, "crypto classification must be compatible", "crypto classification unresolved")
		return
	}

	if mode == config.CryptoModeOnly {
		b.pass(CheckCryptoIdentity, "crypto classification must be compatible",
			"crypto program", "crypto.mode=only")
		return
	}

	b.pass(CheckCryptoIdentity, "crypto classification must be compatible",
		"crypto classification is "+string(p.CryptoKind), "compatible with crypto.mode="+string(mode))

	// Platform-only mode is the blunt instrument: it admits a crypto business
	// and rejects everything else, including mixed programs.
	if mode == config.CryptoModePlatformOnly {
		if p.CryptoKind == domain.CryptoPlatform {
			b.pass(CheckCryptoAllowed, "crypto program must have platform character",
				"crypto platform", "crypto.mode=platform_only")
		} else {
			b.fail(CheckCryptoAllowed, "crypto program must have platform character",
				"crypto classification is "+string(p.CryptoKind), "crypto.mode=platform_only", "")
		}
		return
	}

	traits := domain.FromTags(p.CryptoTraits)
	allowed := e.profile.AllowedCryptoTraits()
	excluded := e.profile.ExcludedCryptoTraits()

	if len(allowed) == 0 && e.profile.Crypto.RequireAllowedTrait {
		b.fail(CheckCryptoAllowed, "crypto program must carry an allowed trait",
			"no allowed crypto traits are configured", "at least one allowed trait must be configured", "")
	} else if len(allowed) == 0 {
		b.skip(CheckCryptoAllowed, "crypto program must carry an allowed trait",
			"the profile lists no allowed crypto traits and does not require one")
	} else if traits.HasAnyString(toStrings(allowed)...) {
		b.pass(CheckCryptoAllowed, "crypto program must carry an allowed trait",
			"carries "+domain.NewTags(toStrings(intersectTraits(traits, allowed))...).Join(),
			"one of "+domain.NewTags(toStrings(allowed)...).Join())
	} else {
		b.fail(CheckCryptoAllowed, "crypto program must carry an allowed trait",
			"carries "+traits.Tags().Join(), "one of "+domain.NewTags(toStrings(allowed)...).Join(), "")
	}

	if len(excluded) == 0 {
		b.skip(CheckCryptoExcluded, "excluded crypto traits must not dominate",
			"the profile excludes no crypto traits")
		return
	}

	excludedHits := intersectTraits(traits, excluded)
	if len(excludedHits) == 0 {
		b.pass(CheckCryptoExcluded, "excluded crypto traits must not dominate",
			"no excluded crypto traits present", "excluded: "+domain.NewTags(toStrings(excluded)...).Join())
		return
	}

	ratio := float64(len(excludedHits)) / float64(len(traits))
	if ratio >= e.profile.CryptoDominanceRatio() {
		b.fail(CheckCryptoExcluded, "excluded crypto traits must not dominate",
			"program is predominantly "+excludedHits.Tags().Join(),
			"less than "+pct(e.profile.CryptoDominanceRatio())+" excluded crypto character", "")
		return
	}
	b.pass(CheckCryptoExcluded, "excluded crypto traits must not dominate",
		"excluded crypto traits are a minority of "+traits.Tags().Join(),
		"less than "+pct(e.profile.CryptoDominanceRatio())+" excluded crypto character")
}

// intersectTraits returns the members of a present in b.
func intersectTraits(a, b domain.CryptoTraits) domain.CryptoTraits {
	out := make(domain.CryptoTraits, 0)
	for _, t := range a {
		if b.Has(t) {
			out = append(out, t)
		}
	}
	return out
}

func toStrings(ts domain.CryptoTraits) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func stateList(states []domain.ProgramState) string {
	parts := make([]string, 0, len(states))
	for _, s := range states {
		parts = append(parts, string(s))
	}
	return strings.Join(parts, ", ")
}

func describeTags(t domain.Tags) string {
	if len(t) == 0 {
		return "nothing"
	}
	return t.Join()
}

func usd(v float64) string { return fmt.Sprintf("$%.2f", v) }

func pct(r float64) string { return fmt.Sprintf("%.0f%%", r*100) }

func itoa(n int) string { return fmt.Sprintf("%d", n) }
