package domain

// CryptoKind is the coarse verdict about a program's relationship to crypto.
//
// The distinction that matters most in practice is between a crypto *business*
// whose attack surface is ordinary web, API, and backend engineering, and pure
// protocol or smart-contract research. Treating every crypto program as relevant
// is the fastest way to make an alert channel useless.
type CryptoKind string

const (
	// CryptoNotCrypto means the program has no crypto character.
	CryptoNotCrypto CryptoKind = "not_crypto"
	// CryptoPlatform means a crypto product or company with web, API,
	// backend, authentication, or infrastructure attack surface.
	CryptoPlatform CryptoKind = "crypto_platform"
	// CryptoSmartContract means the program is limited to smart contracts and
	// on-chain code.
	CryptoSmartContract CryptoKind = "smart_contract_only"
	// CryptoProtocol means the program targets protocol, consensus, node, or
	// cryptographic-primitive research.
	CryptoProtocol CryptoKind = "protocol_research"
	// CryptoMixed means both platform and protocol surfaces are present, so
	// the program cannot be classified as either without guessing.
	CryptoMixed CryptoKind = "mixed"
	// CryptoUnknown means crypto character was suggested but not resolvable.
	CryptoUnknown CryptoKind = "unknown"
)

// Crypto trait identifiers.
//
// These are the units the profile's crypto allow/deny lists are written against.
// Classification emits traits; policy compares traits. Keeping the vocabulary in
// the domain means a new profile can name a trait without touching the engine.
const (
	// CryptoTraitPlatform marks a crypto business or product.
	CryptoTraitPlatform CryptoTrait = "crypto_platform"

	// Positive platform-shaped traits.
	CryptoTraitExchange       CryptoTrait = "exchange"
	CryptoTraitWallet         CryptoTrait = "wallet_platform"
	CryptoTraitFintech        CryptoTrait = "fintech_crypto"
	CryptoTraitWebApp         CryptoTrait = "crypto_web_application"
	CryptoTraitAPI            CryptoTrait = "crypto_api"
	CryptoTraitBackend        CryptoTrait = "crypto_backend"
	CryptoTraitInfrastructure CryptoTrait = "crypto_infrastructure"
	CryptoTraitUserFacing     CryptoTrait = "user_facing_application"

	// Protocol-shaped traits, typically excluded for web/API researchers.
	CryptoTraitSmartContract  CryptoTrait = "smart_contract_only"
	CryptoTraitSolidityOnly   CryptoTrait = "solidity_only"
	CryptoTraitConsensus      CryptoTrait = "protocol_consensus"
	CryptoTraitCoreProtocol   CryptoTrait = "blockchain_core_protocol"
	CryptoTraitCryptoResearch CryptoTrait = "cryptographic_primitive_research"
)

// CryptoTrait is one classified crypto characteristic.
type CryptoTrait string

// String satisfies fmt.Stringer.
func (t CryptoTrait) String() string { return string(t) }

// CryptoTraits is a set of crypto characteristics.
type CryptoTraits []CryptoTrait

// AllCryptoTraits lists the vocabulary in a stable order for configuration
// validation and documentation.
func AllCryptoTraits() []CryptoTrait {
	return []CryptoTrait{
		CryptoTraitPlatform,
		CryptoTraitExchange,
		CryptoTraitWallet,
		CryptoTraitFintech,
		CryptoTraitWebApp,
		CryptoTraitAPI,
		CryptoTraitBackend,
		CryptoTraitInfrastructure,
		CryptoTraitUserFacing,
		CryptoTraitSmartContract,
		CryptoTraitSolidityOnly,
		CryptoTraitConsensus,
		CryptoTraitCoreProtocol,
		CryptoTraitCryptoResearch,
	}
}

// ParseCryptoTrait validates a configured trait name.
func ParseCryptoTrait(s string) (CryptoTrait, bool) {
	v := CryptoTrait(NormalizeTag(s))
	for _, t := range AllCryptoTraits() {
		if t == v {
			return t, true
		}
	}
	return "", false
}

// Tags projects the trait set into the generic tag representation used for
// fingerprinting and policy comparison.
func (ts CryptoTraits) Tags() Tags {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return NewTags(out...)
}

// FromTags rebuilds a trait set from the tag representation, discarding values
// outside the known vocabulary.
func FromTags(tags Tags) CryptoTraits {
	known := make(map[string]CryptoTrait, len(AllCryptoTraits()))
	for _, t := range AllCryptoTraits() {
		known[string(t)] = t
	}
	out := make(CryptoTraits, 0, len(tags))
	for _, tag := range tags {
		if t, ok := known[tag]; ok {
			out = append(out, t)
		}
	}
	return out
}

// Has reports whether the trait is present.
func (ts CryptoTraits) Has(t CryptoTrait) bool {
	for _, x := range ts {
		if x == t {
			return true
		}
	}
	return false
}

// platformTraits are the traits that indicate a crypto business with ordinary
// software attack surface.
var platformTraits = []CryptoTrait{
	CryptoTraitPlatform,
	CryptoTraitExchange,
	CryptoTraitWallet,
	CryptoTraitFintech,
	CryptoTraitWebApp,
	CryptoTraitAPI,
	CryptoTraitBackend,
	CryptoTraitInfrastructure,
	CryptoTraitUserFacing,
}

// protocolTraits are the traits that indicate on-chain or protocol research.
var protocolTraits = []CryptoTrait{
	CryptoTraitSmartContract,
	CryptoTraitSolidityOnly,
	CryptoTraitConsensus,
	CryptoTraitCoreProtocol,
	CryptoTraitCryptoResearch,
}

func (ts CryptoTraits) hasAny(list []CryptoTrait) bool {
	for _, t := range list {
		if ts.Has(t) {
			return true
		}
	}
	return false
}

// DeriveCryptoKind collapses a trait set into a single verdict.
//
// The rules are deliberately explicit and total, with no heuristics that depend
// on magnitude: an ambiguity resolves to CryptoMixed rather than to whichever
// bucket happens to have more evidence. Smart-contract and consensus traits are
// both protocol-side, so a program carrying both is still protocol research
// rather than a mixture; only platform character alongside protocol traits is a
// genuine mixture that cannot be resolved without guessing.
func DeriveCryptoKind(ts CryptoTraits) CryptoKind {
	platform := ts.hasAny(platformTraits)
	contract := ts.Has(CryptoTraitSmartContract) || ts.Has(CryptoTraitSolidityOnly)
	protocol := ts.hasAny(protocolTraits)
	switch {
	case !platform && !contract && !protocol:
		return CryptoNotCrypto
	case platform && (contract || protocol):
		return CryptoMixed
	case platform:
		return CryptoPlatform
	case contract:
		return CryptoSmartContract
	default:
		return CryptoProtocol
	}
}

// HasAnyString reports whether any of the given trait names is present.
func (ts CryptoTraits) HasAnyString(names ...string) bool {
	for _, n := range names {
		if ts.Has(CryptoTrait(n)) {
			return true
		}
	}
	return false
}

// PlatformTraits returns the traits that indicate a crypto business with
// ordinary software attack surface.
//
// Exported so that classification can assert the platform trait without
// duplicating the vocabulary.
func PlatformTraits() CryptoTraits { return append(CryptoTraits(nil), platformTraits...) }

// ProtocolTraits returns the traits that indicate protocol research.
func ProtocolTraits() CryptoTraits { return append(CryptoTraits(nil), protocolTraits...) }
