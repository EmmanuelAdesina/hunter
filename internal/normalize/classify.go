// Package normalize converts adapter output into the canonical domain model.
//
// Two responsibilities live here, and they are deliberately separated from both
// the adapter and the policy engine:
//
//  1. Structural normalization: parsing dates and numbers, mapping source
//     vocabularies onto domain enums, and building the canonical record.
//  2. Classification: deciding what technical surface a program exposes, and -
//     most importantly - whether a crypto program is a crypto *business* with
//     ordinary software attack surface or pure protocol research.
//
// Classification emits evidence-bearing traits. Policy decides what to do with
// them. Keeping that split means a researcher can change their crypto stance in
// configuration without touching any classification logic.
package normalize

import (
	"sort"
	"strings"

	"github.com/eadeshina/hunter/internal/domain"
)

// cryptoSignal is one piece of evidence for a crypto trait.
type cryptoSignal struct {
	trait domain.CryptoTrait
	// weight lets a strong signal outweigh a weak one when the same trait is
	// implied by several different phrases.
	weight int
	// why records the evidence, so a classification can be explained.
	why string
}

// cryptoKeyword maps a phrase to the traits it implies.
//
// Evidence is drawn from three independent places: the program's own
// classification labels, its scope descriptions, and its prose. Relying on any
// one of them alone would misclassify: labels are coarse, scope titles are
// sparse, and prose is noisy.
var cryptoKeyword = map[string][]cryptoSignal{
	// Platform identity: the program is about a crypto product or company.
	"exchange":  {{domain.CryptoTraitExchange, 3, "describes itself as an exchange"}},
	"cex":       {{domain.CryptoTraitExchange, 3, "classified as a centralised exchange"}},
	"dex":       {{domain.CryptoTraitExchange, 1, "mentions a decentralised exchange"}},
	"wallet":    {{domain.CryptoTraitWallet, 3, "describes a wallet product"}},
	"custody":   {{domain.CryptoTraitWallet, 2, "mentions custody"}},
	"custodial": {{domain.CryptoTraitWallet, 2, "mentions custodial products"}},
	"fintech":   {{domain.CryptoTraitFintech, 2, "classified as fintech"}},
	"neobank":   {{domain.CryptoTraitFintech, 2, "classified as a digital bank"}},

	// Platform attack surface: the software a user or integrator touches.
	"api":             {{domain.CryptoTraitAPI, 2, "exposes an API"}},
	"rest api":        {{domain.CryptoTraitAPI, 3, "exposes a REST API"}},
	"graphql":         {{domain.CryptoTraitAPI, 3, "exposes a GraphQL API"}},
	"web app":         {{domain.CryptoTraitWebApp, 3, "has a web application"}},
	"web application": {{domain.CryptoTraitWebApp, 3, "has a web application"}},
	"mobile app":      {{domain.CryptoTraitUserFacing, 2, "has a mobile application"}},
	"backend":         {{domain.CryptoTraitBackend, 2, "mentions backend services"}},
	"admin panel":     {{domain.CryptoTraitBackend, 2, "exposes an administrative interface"}},
	"internal api":    {{domain.CryptoTraitBackend, 2, "mentions internal APIs"}},

	// Protocol research surface: on-chain and cryptographic.
	"smart contract":        {{domain.CryptoTraitSmartContract, 4, "scope is smart contracts"}},
	"smart contracts":       {{domain.CryptoTraitSmartContract, 4, "scope is smart contracts"}},
	"solidity":              {{domain.CryptoTraitSolidityOnly, 4, "mentions Solidity"}},
	"consensus":             {{domain.CryptoTraitConsensus, 4, "mentions consensus"}},
	"validator":             {{domain.CryptoTraitConsensus, 3, "targets validators"}},
	"stake":                 {{domain.CryptoTraitConsensus, 2, "targets staking"}},
	"staking":               {{domain.CryptoTraitConsensus, 2, "targets staking"}},
	"node":                  {{domain.CryptoTraitCoreProtocol, 3, "targets nodes"}},
	"full node":             {{domain.CryptoTraitCoreProtocol, 4, "targets full nodes"}},
	"protocol":              {{domain.CryptoTraitCoreProtocol, 3, "targets the protocol"}},
	"cryptography research": {{domain.CryptoTraitCryptoResearch, 4, "targets cryptographic research"}},
	"zero knowledge":        {{domain.CryptoTraitCryptoResearch, 4, "targets zero-knowledge research"}},
	"zk proof":              {{domain.CryptoTraitCryptoResearch, 4, "targets zero-knowledge proofs"}},
	"blockchain core":       {{domain.CryptoTraitCoreProtocol, 4, "targets the blockchain core"}},
}

// cryptoIdentityPhrase marks a program as crypto-related in the first place.
//
// Identity is established before traits, so that a program with no crypto
// vocabulary is classified as non-crypto rather than acquiring traits from an
// incidental mention of a wallet.
var cryptoIdentityPhrase = map[string]int{
	"crypto":         3,
	"cex":            3,
	"dex":            3,
	"defi protocol":  2,
	"cryptocurrency": 3,
	"blockchain":     2,
	"defi":           3,
	"web3":           3,
	"nft":            2,
	"token":          1,
	"bitcoin":        3,
	"ethereum":       3,
	"stablecoin":     3,
	"on-chain":       2,
	"onchain":        2,
}

// surfaceTagByKind maps a target kind onto the profile's surface vocabulary.
//
// The profile names surfaces the way a researcher thinks about them
// ("web_application", "api", "backend", "codebase"), so the mapping is explicit
// rather than inferred from string similarity.
var surfaceTagByKind = map[domain.TargetKind]string{
	domain.KindWeb:            "web_application",
	domain.KindAPI:            "api",
	domain.KindRepository:     "codebase",
	domain.KindDomain:         "domain",
	domain.KindInfrastructure: "infrastructure",
	domain.KindCloud:          "cloud",
	domain.KindMobile:         "mobile",
	domain.KindApplication:    "application",
	domain.KindSmartContract:  "smart_contract",
	domain.KindProtocol:       "protocol",
}

// classifyCrypto derives crypto traits and a verdict for a program.
//
// The inputs are passed separately rather than as a finished program so that
// classification can be tested in isolation from normalization.
type cryptoInput struct {
	// ProjectTypes and categories are the source's own labels.
	ProjectTypes []string
	Categories   []string
	// ScopeText is the concatenated scope titles and target descriptions.
	ScopeText string
	// Description and scopeNotes are the program's prose.
	Description string
	ScopeNotes  string
	// TargetKinds are the normalized kinds of the program's assets.
	TargetKinds []domain.TargetKind
}

// cryptoResult is the outcome of classification.
type cryptoResult struct {
	Kind     domain.CryptoKind
	Traits   domain.CryptoTraits
	Evidence []string
}

// classifyCrypto determines whether a program is a crypto business with
// ordinary software attack surface, pure protocol research, both, or neither.

// classifyCrypto determines whether a program is a crypto business with
// ordinary software attack surface, pure protocol research, both, or neither.
//
// The evidence sources are deliberately kept apart:
//
//   - Structured signals (asset kinds, the source's own classification labels,
//     and scope titles and descriptions) decide *traits*.
//   - Free prose (the program description and the stated scope of
//     vulnerabilities) decides only *whether the program is crypto at all*.
//
// Keeping prose out of trait assignment is what stops a smart-contract program
// whose marketing copy happens to mention "web3" from being reclassified as a
// crypto platform, which would admit exactly the programs the profile exists to
// exclude.
func classifyCrypto(in cryptoInput) cryptoResult {
	weights := make(map[domain.CryptoTrait]int, 8)
	evidence := make(map[domain.CryptoTrait]string, 8)

	record := func(trait domain.CryptoTrait, weight int, why string) {
		weights[trait] += weight
		// Keep the strongest single piece of evidence for the explanation.
		if _, seen := evidence[trait]; !seen || weight > 2 {
			evidence[trait] = why
		}
	}

	// Structured text: labels plus scope titles and descriptions.
	structured := strings.ToLower(in.ScopeText + " " +
		strings.Join(in.ProjectTypes, " ") + " " + strings.Join(in.Categories, " "))

	// Step 1: traits implied by what is actually in scope.
	for _, kind := range in.TargetKinds {
		switch kind {
		case domain.KindWeb, domain.KindApplication:
			record(domain.CryptoTraitWebApp, 2, "has a web application in scope")
		case domain.KindAPI:
			record(domain.CryptoTraitAPI, 3, "has an API in scope")
		case domain.KindRepository:
			record(domain.CryptoTraitBackend, 1, "publishes a repository in scope")
		case domain.KindInfrastructure, domain.KindCloud:
			record(domain.CryptoTraitInfrastructure, 2, "has infrastructure or cloud in scope")
		case domain.KindMobile:
			record(domain.CryptoTraitUserFacing, 2, "has a mobile application in scope")
		case domain.KindSmartContract:
			record(domain.CryptoTraitSmartContract, 3, "has smart contracts in scope")
		case domain.KindProtocol:
			record(domain.CryptoTraitCoreProtocol, 2, "has protocol or node assets in scope")
		}
	}

	// Step 2: traits implied by structured vocabulary.
	for phrase, signals := range cryptoKeyword {
		if !containsPhrase(structured, phrase) {
			continue
		}
		for _, s := range signals {
			record(s.trait, s.weight, s.why)
		}
	}

	// Step 3: identity. A program is treated as crypto when its labels or its
	// prose say so, or when the structured evidence is unmistakably
	// crypto-specific. Prose participates only here.
	identity := 0
	labelText := strings.ToLower(strings.Join(in.ProjectTypes, " ") + " " + strings.Join(in.Categories, " "))
	for phrase, w := range cryptoIdentityPhrase {
		if containsWord(labelText, phrase) {
			identity += w
		}
	}
	prose := strings.ToLower(in.Description + " " + in.ScopeNotes)
	for phrase, w := range cryptoIdentityPhrase {
		if containsPhrase(prose, phrase) {
			identity += w
		}
	}

	// Unmistakably crypto structured evidence establishes identity on its own, so
	// that a program labelled only "CEX" is still recognized as crypto.
	for _, t := range []domain.CryptoTrait{
		domain.CryptoTraitExchange, domain.CryptoTraitWallet,
		domain.CryptoTraitSmartContract, domain.CryptoTraitSolidityOnly,
		domain.CryptoTraitConsensus, domain.CryptoTraitCoreProtocol,
		domain.CryptoTraitCryptoResearch,
	} {
		if weights[t] > 0 {
			identity += 2
			break
		}
	}

	if identity == 0 {
		return cryptoResult{Kind: domain.CryptoNotCrypto}
	}

	// Step 4: keep only traits with enough evidence to be asserted. A single
	// incidental keyword must not decide a program's classification.
	traits := make(domain.CryptoTraits, 0, len(weights))
	ev := make([]string, 0, len(weights))
	for trait, w := range weights {
		if w < 2 {
			continue
		}
		traits = append(traits, trait)
		if why := evidence[trait]; why != "" {
			ev = append(ev, why)
		}
	}

	// Step 5: platform character. The platform trait asserts that this is a
	// crypto business rather than protocol research, and requires both a crypto
	// identity and at least one platform-shaped signal.
	if len(intersectTraitSet(traits, domain.PlatformTraits())) > 0 {
		traits = append(traits, domain.CryptoTraitPlatform)
		ev = append(ev, "crypto identity with platform-shaped attack surface")
	}

	kind := domain.DeriveCryptoKind(traits)
	if kind == domain.CryptoNotCrypto {
		// The program says it is crypto but nothing structured confirmed a
		// surface. Reporting that explicitly is more useful than claiming it is
		// not crypto, because the profile's allow list would otherwise reject it
		// with no explanation.
		kind = domain.CryptoUnknown
		ev = append(ev, "labelled as crypto but no platform or protocol surface was confirmed from scope")
	}
	sortCryptoTraits(traits)
	return cryptoResult{Kind: kind, Traits: traits, Evidence: ev}
}

// intersectTraitSet returns the members of a present in b.
func intersectTraitSet(a, b []domain.CryptoTrait) domain.CryptoTrait {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

// sortCryptoTraits orders traits so that classification output is deterministic.
func sortCryptoTraits(ts domain.CryptoTraits) {
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
}

// surfaceTags derives the profile-facing technical surface vocabulary.
func surfaceTags(kinds []domain.TargetKind) domain.Tags {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if tag, ok := surfaceTagByKind[k]; ok {
			out = append(out, tag)
		}
	}
	// web2 is an alternative spelling researchers use for the web surface. It
	// is emitted alongside web_application so that either wording in a profile
	// matches, rather than forcing the profile author to guess which spelling
	// the system uses.
	if containsStr(out, "web_application") {
		out = append(out, "web2")
	}
	return domain.NewTags(out...)
}

// capabilityTags derives attack-surface characteristics from scope prose.
//
// These describe what a researcher could actually test, which is what makes
// triage useful beyond a surface count. Matching is phrase-based and
// conservative: a capability is only asserted when the program explicitly
// discusses the corresponding surface.
var capabilityPatterns = map[string][]string{
	"authentication":  {"authentication", "login", "sign-in", "sign up", "signup", "session", "2fa", "mfa", "oauth", "sso", "password reset"},
	"authorization":   {"authorization", "access control", "idor", "privilege escalation", "rbac", "permissions", "role"},
	"user_accounts":   {"user account", "accounts", "account takeover", "user data", "pii", "profile"},
	"payments":        {"payment", "withdrawal", "deposit", "transfer", "balance", "transaction", "refund", "invoice"},
	"trading":         {"trading", "order book", "liquidity", "perp", "futures", "options", "swap"},
	"admin_interface": {"admin panel", "administrative", "internal tool", "back office", "dashboard"},
	"api":             {"api", "endpoint", "webhook", "sdk"},
	"integrations":    {"integration", "third party", "partner", "webhook"},
	"file_handling":   {"upload", "file upload", "download", "attachment"},
	"graphql":         {"graphql"},
}

func capabilityTags(scopeText string) domain.Tags {
	lower := strings.ToLower(scopeText)
	out := make([]string, 0, len(capabilityPatterns))
	for tag, phrases := range capabilityPatterns {
		for _, p := range phrases {
			if containsPhrase(lower, p) {
				out = append(out, tag)
				break
			}
		}
	}
	return domain.NewTags(out...)
}

// containsWord reports whether text contains a word-boundary match of word.
func containsWord(text, word string) bool {
	idx := 0
	for {
		found := strings.Index(text[idx:], word)
		if found < 0 {
			return false
		}
		start := idx + found
		end := start + len(word)
		beforeOK := start == 0 || !isWordByte(text[start-1])
		afterOK := end == len(text) || !isWordByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		idx = start + 1
	}
}

// containsPhrase reports whether text contains phrase, tolerating whitespace
// runs and punctuation at the boundaries.
func containsPhrase(text, phrase string) bool {
	compact := strings.Join(strings.Fields(text), " ")
	return strings.Contains(compact, phrase)
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
