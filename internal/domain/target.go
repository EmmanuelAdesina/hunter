package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// TargetKind is the technical surface a target represents.
//
// A source may use any vocabulary it likes ("Web", "API", "Android App"); the
// adapter maps it to exactly one of these kinds so that policy and scoring never
// depend on source-specific strings.
type TargetKind string

const (
	KindWeb            TargetKind = "web"
	KindAPI            TargetKind = "api"
	KindRepository     TargetKind = "repository"
	KindDomain         TargetKind = "domain"
	KindApplication    TargetKind = "application"
	KindInfrastructure TargetKind = "infrastructure"
	KindCloud          TargetKind = "cloud"
	KindMobile         TargetKind = "mobile"
	KindSmartContract  TargetKind = "smart_contract"
	KindProtocol       TargetKind = "protocol"
	KindOther          TargetKind = "other"
)

// AllTargetKinds lists every kind in stable order, for configuration validation
// and for diagnostics. Keeping it here avoids scattering string literals.
func AllTargetKinds() []TargetKind {
	return []TargetKind{
		KindWeb, KindAPI, KindRepository, KindDomain, KindApplication,
		KindInfrastructure, KindCloud, KindMobile, KindSmartContract,
		KindProtocol, KindOther,
	}
}

// ParseTargetKind validates a configured kind name.
func ParseTargetKind(s string) (TargetKind, bool) {
	v := TargetKind(NormalizeTag(s))
	for _, k := range AllTargetKinds() {
		if k == v {
			return k, true
		}
	}
	return KindOther, false
}

// Target is one in-scope or out-of-scope asset of a program.
type Target struct {
	// Kind is the normalized technical surface.
	Kind TargetKind `json:"kind"`

	// Identifier is the asset as the source presents it, e.g. "*.bitrue.com"
	// or "https://api.example.com". It is preserved verbatim so that the
	// researcher can copy it directly into a browser or scanner.
	Identifier string `json:"identifier"`

	// Label is the source's own title for the asset, e.g. "API".
	Label string `json:"label,omitempty"`

	// Description is the free-text annotation attached to the asset.
	Description string `json:"description,omitempty"`

	// InScope is false when the source explicitly lists the asset as excluded.
	// An asset that the source does not classify at all is recorded as in
	// scope, which is how bug-bounty scopes are conventionally read.
	InScope bool `json:"in_scope"`

	// SourceID is the source's own stable identifier for the asset, used to
	// survive cosmetic renames of the label.
	SourceID string `json:"source_id,omitempty"`
}

// Targets is a list of program targets.
type Targets []Target

// InScope returns only the assets the source marked as testable.
func (t Targets) InScope() Targets {
	out := make(Targets, 0, len(t))
	for _, x := range t {
		if x.InScope {
			out = append(out, x)
		}
	}
	return out
}

// Kinds returns the distinct kinds present, sorted.
func (t Targets) Kinds() Tags {
	kinds := make(Tags, 0, len(t))
	for _, x := range t {
		kinds = append(kinds, string(x.Kind))
	}
	return NewTags(kinds...)
}

// OfKind returns the targets matching a kind.
func (t Targets) OfKind(k TargetKind) Targets {
	out := make(Targets, 0)
	for _, x := range t {
		if x.Kind == k {
			out = append(out, x)
		}
	}
	return out
}

// sortTargets orders targets deterministically: kind, then identifier, then
// source ID. Ordering by content rather than by the order the source happened to
// list them is what keeps scope fingerprints stable across runs.
func sortTargets(ts []Target) {
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].Kind != ts[j].Kind {
			return ts[i].Kind < ts[j].Kind
		}
		if ts[i].Identifier != ts[j].Identifier {
			return ts[i].Identifier < ts[j].Identifier
		}
		return ts[i].SourceID < ts[j].SourceID
	})
}

// Fingerprint returns a stable content hash over the in-scope target set.
//
// Only InScope assets participate. An asset being moved into the excluded list
// is a scope change that the scope event already reports; folding it into this
// hash as well would double-count a single semantic change.
func (t Targets) Fingerprint() string {
	scope := t.InScope()
	cp := append(Targets(nil), scope...)
	sortTargets(cp)

	h := sha256.New()
	for _, x := range cp {
		// Length-prefixing prevents field-boundary ambiguity between
		// adjacent targets.
		writeField(h, string(x.Kind))
		writeField(h, normalizeTargetIdentifier(x.Identifier))
		writeField(h, strings.TrimSpace(x.Label))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeTargetIdentifier canonicalizes an identifier for comparison only.
//
// Source identifiers vary in scheme, trailing slashes, case, and host casing.
// Normalizing the host and default ports lets "https://API.Example.com/" and
// "api.example.com" compare equal, which prevents a false "target added" event
// when nothing actually changed.
func normalizeTargetIdentifier(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			host = strings.TrimSuffix(host, ":443")
			host = strings.TrimSuffix(host, ":80")
			rest := strings.TrimSuffix(u.Path, "/")
			return host + rest
		}
	}
	return strings.TrimSuffix(lower, "/")
}

// KindOfTitle maps a source-provided asset title onto a TargetKind.
//
// Titles are coarse hints, never the sole basis for a decision: "Web" and "API"
// are trustworthy, while an unrecognised title falls back to inference over the
// identifier in InferTargetKind.
func KindOfTitle(title string) (TargetKind, bool) {
	switch NormalizeTag(title) {
	case "web", "web application", "webapp", "web app", "website", "site":
		return KindWeb, true
	case "api", "apis", "rest api", "graphql", "grpc":
		return KindAPI, true
	case "mobile", "android", "ios", "android app", "ios app", "mobile app":
		return KindMobile, true
	case "smart contract", "smart contracts", "contracts", "evm", "solidity":
		return KindSmartContract, true
	case "protocol", "blockchain", "consensus", "node", "validator":
		return KindProtocol, true
	case "repo", "repository", "repositories", "source code", "codebase", "github":
		return KindRepository, true
	case "cloud", "aws", "gcp", "azure", "cloud infrastructure":
		return KindCloud, true
	case "infrastructure", "infra":
		return KindInfrastructure, true
	case "domain", "domains", "dns":
		return KindDomain, true
	case "app", "application", "desktop app":
		return KindApplication, true
	default:
		return KindOther, false
	}
}

// InferTargetKind derives a kind from the identifier when the title is absent
// or unrecognized. Evidence is ordered from most to least specific.
func InferTargetKind(identifier string) TargetKind {
	s := strings.ToLower(strings.TrimSpace(identifier))
	switch {
	case s == "":
		return KindOther
	case strings.Contains(s, "github.com") || strings.Contains(s, "gitlab.com") ||
		strings.Contains(s, "bitbucket.org") || strings.Contains(s, "/blob/") ||
		strings.Contains(s, "codeberg"):
		return KindRepository
	case strings.HasSuffix(s, ".sol") || strings.HasPrefix(s, "solidity:"):
		return KindSmartContract
	case strings.Contains(s, "play.google.com") || strings.Contains(s, "apps.apple.com"):
		return KindMobile
	case strings.Contains(s, "swagger") || strings.Contains(s, "openapi") ||
		strings.Contains(s, "api-docs") || strings.Contains(s, "apidocs") ||
		strings.Contains(s, "/api") || strings.Contains(s, "graphiql") ||
		strings.Contains(s, ".readme") && strings.Contains(s, "api"):
		return KindAPI
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.Contains(s, ".com") || strings.Contains(s, ".io") ||
		strings.Contains(s, ".net") || strings.Contains(s, ".app") ||
		strings.Contains(s, ".xyz") || strings.Contains(s, ".org"):
		return KindWeb
	case strings.Contains(s, "aws") || strings.Contains(s, "gcp") ||
		strings.Contains(s, "azure") || strings.Contains(s, "s3://"):
		return KindCloud
	default:
		return KindOther
	}
}

// writeField writes a length-prefixed field to a hash so that concatenation
// ambiguity between adjacent fields cannot occur.
func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	fmt.Fprintf(h, "%d:%s|", len(s), s)
}
