package normalize_test

import (
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/normalize"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func normalizeWith(raw domain.RawProgram) domain.Program {
	return normalize.Program(raw, normalize.Options{Now: func() time.Time { return fixedNow }})
}

// baseRaw builds a parseable record that tests then vary.
func baseRaw(mutators ...func(*domain.RawProgram)) domain.RawProgram {
	raw := domain.RawProgram{
		Ref:             domain.ProgramRef{Source: "hackenproof", ID: "example", Slug: "example", Name: "Example"},
		Parsed:          true,
		Name:            "Example",
		Status:          "LIVE",
		State:           "published",
		Reputation:      domain.ReputationGate{Present: domain.TriNo},
		Fee:             domain.FeeGate{Present: domain.TriNo},
		KYC:             domain.TriNo,
		POC:             domain.TriYes,
		MinBountyRaw:    "100.0",
		MaxBountyRaw:    "5000.0",
		CategoriesRaw:   []string{"Web", "API"},
		ProjectTypesRaw: []string{"CEX"},
		Scopes: []domain.RawScope{
			{Title: "Web", Target: "*.example.com", OutOfScope: false},
			{Title: "API", Target: "https://api.example.com", OutOfScope: false},
		},
	}
	for _, m := range mutators {
		m(&raw)
	}
	return raw
}

// TestBasicNormalization verifies the canonical record is built correctly.
func TestBasicNormalization(t *testing.T) {
	p := normalizeWith(baseRaw())

	if p.ID != "hackenproof:example" {
		t.Errorf("ID = %q, want hackenproof:example", p.ID)
	}
	if p.State != domain.StateLive {
		t.Errorf("state = %s, want live", p.State)
	}
	if p.KYC != domain.TriNo || p.Reputation.Present != domain.TriNo {
		t.Errorf("access facts not carried: kyc=%s reputation=%s", p.KYC, p.Reputation.Present)
	}
	if p.MaxBountyUSD == nil || *p.MaxBountyUSD != 5000 {
		t.Errorf("max bounty = %v, want 5000", p.MaxBountyUSD)
	}
	if p.MinBountyUSD == nil || *p.MinBountyUSD != 100 {
		t.Errorf("min bounty = %v, want 100", p.MinBountyUSD)
	}
	if p.ProjectTypes.String() != "cex" {
		t.Errorf("project types = %q, want cex", p.ProjectTypes)
	}
	if len(p.InScopeTargets()) != 2 {
		t.Errorf("in-scope targets = %d, want 2", len(p.InScopeTargets()))
	}
	if p.ParseConfidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %s, want high", p.ParseConfidence)
	}
}

// TestFingerprintsAreDeterministic verifies identical input yields identical
// fingerprints, and that any real change moves them.
func TestFingerprintsAreDeterministic(t *testing.T) {
	a := normalizeWith(baseRaw())
	b := normalizeWith(baseRaw())
	if a.ScopeFingerprint != b.ScopeFingerprint {
		t.Error("scope fingerprint is not deterministic")
	}
	if a.RequirementFingerprint != b.RequirementFingerprint {
		t.Error("requirement fingerprint is not deterministic")
	}
	if a.MetadataFingerprint != b.MetadataFingerprint {
		t.Error("metadata fingerprint is not deterministic")
	}

	withExtraScope := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.Scopes = append(r.Scopes, domain.RawScope{Title: "API", Target: "https://api-v2.example.com"})
	}))
	if withExtraScope.ScopeFingerprint == a.ScopeFingerprint {
		t.Error("an added asset did not change the scope fingerprint")
	}
	if withExtraScope.MetadataFingerprint != a.MetadataFingerprint {
		t.Error("a scope change leaked into the metadata fingerprint")
	}

	kycChanged := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.KYC = domain.TriYes }))
	if kycChanged.RequirementFingerprint == a.RequirementFingerprint {
		t.Error("a KYC change did not move the requirement fingerprint")
	}
	if kycChanged.ScopeFingerprint != a.ScopeFingerprint {
		t.Error("a KYC change moved the scope fingerprint")
	}

	bountyChanged := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.MaxBountyRaw = "9000.0" }))
	if bountyChanged.MetadataFingerprint == a.MetadataFingerprint {
		t.Error("a bounty change did not move the metadata fingerprint")
	}
}

// TestTargetOrderingDoesNotAffectFingerprint verifies the source's ordering is
// irrelevant, which is what stops spurious scope-change reports.
func TestTargetOrderingDoesNotAffectFingerprint(t *testing.T) {
	forward := baseRaw()
	reversed := baseRaw(func(r *domain.RawProgram) {
		a, b := r.Scopes[0], r.Scopes[1]
		r.Scopes = []domain.RawScope{b, a}
	})
	if normalizeWith(forward).ScopeFingerprint != normalizeWith(reversed).ScopeFingerprint {
		t.Error("reordering the source's asset list changed the scope fingerprint")
	}
}

// TestOutOfScopeAssetsAreExcludedFromScopeFingerprint verifies moving an asset
// to the excluded list is a removal, not a rename.
func TestOutOfScopeAssetsAreExcludedFromScopeFingerprint(t *testing.T) {
	inScope := baseRaw()
	excluded := baseRaw(func(r *domain.RawProgram) {
		r.Scopes[1].OutOfScope = true
	})
	if normalizeWith(inScope).ScopeFingerprint == normalizeWith(excluded).ScopeFingerprint {
		t.Error("excluding an asset did not change the scope fingerprint")
	}
}

// TestCosmeticIdentifierChangesAreIgnored verifies scheme and casing changes
// do not register as a new asset.
func TestCosmeticIdentifierChangesAreIgnored(t *testing.T) {
	plain := baseRaw()
	variant := baseRaw(func(r *domain.RawProgram) {
		r.Scopes[0].Target = "https://*.example.com/"
	})
	if normalizeWith(plain).ScopeFingerprint != normalizeWith(variant).ScopeFingerprint {
		t.Error("a cosmetic URL change altered the scope fingerprint")
	}
}

// TestTargetKindInference verifies source titles map onto canonical kinds and
// unknown titles fall back to the identifier.
func TestTargetKindInference(t *testing.T) {
	cases := []struct {
		title string
		want  domain.TargetKind
	}{
		{"Web", domain.KindWeb},
		{"API", domain.KindAPI},
		{"Android App", domain.KindMobile},
		{"iOS App", domain.KindMobile},
		{"Smart Contract", domain.KindSmartContract},
		{"Repository", domain.KindRepository},
		{"Cloud", domain.KindCloud},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
				r.Scopes = []domain.RawScope{{Title: tc.title, Target: "asset.example.com"}}
			}))
			kinds := p.Targets.Kinds()
			if !kinds.Has(string(tc.want)) {
				t.Errorf("kind = %v, want %s", kinds, tc.want)
			}
		})
	}

	t.Run("unknown title falls back to the identifier", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
			r.Scopes = []domain.RawScope{{Title: "thing", Target: "https://github.com/example/repo"}}
		}))
		if !p.Targets.Kinds().Has(string(domain.KindRepository)) {
			t.Errorf("kind = %v, want repository inferred from the URL", p.Targets.Kinds())
		}
	})
}

// TestParseConfidenceReflectsUnknownFacts verifies confidence drops when an
// access fact cannot be read, which is what causes quarantine.
func TestParseConfidenceReflectsUnknownFacts(t *testing.T) {
	t.Run("unknown kyc lowers confidence", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.KYC = domain.TriUnknown }))
		if p.ParseConfidence != domain.ConfidenceLow {
			t.Errorf("confidence = %s, want low when KYC is unknown", p.ParseConfidence)
		}
	})
	t.Run("unknown status lowers confidence", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.Status = "brand-new-status" }))
		if p.ParseConfidence != domain.ConfidenceLow {
			t.Errorf("confidence = %s, want low for an unrecognized status", p.ParseConfidence)
		}
	})
	t.Run("unparsed record is low confidence", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.Parsed = false }))
		if p.ParseConfidence != domain.ConfidenceLow {
			t.Errorf("confidence = %s, want low for an unparsed record", p.ParseConfidence)
		}
		if len(p.ParseIssues) == 0 {
			t.Error("an unparsed record recorded no parse issues")
		}
	})
}

// TestUnknownLifecycleStateIsNotAssumedLive verifies an unrecognized status is
// never read as accepting reports.
func TestUnknownLifecycleStateIsNotAssumedLive(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.Status = "brand-new-status" }))
	if p.State != domain.StateUnknown {
		t.Errorf("state = %s, want unknown", p.State)
	}
	if p.AcceptsReports() {
		t.Error("a program with an unknown state was treated as accepting reports")
	}
	if p.RawStatus != "brand-new-status" {
		t.Errorf("raw status = %q, want the source vocabulary preserved", p.RawStatus)
	}
}

// TestDateParsing verifies dates are parsed or left absent, never defaulted.
func TestDateParsing(t *testing.T) {
	t.Run("recognized format", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
			r.RawDates.Start = "08 Feb 2022"
		}))
		if p.StartedAt == nil {
			t.Fatal("a recognized date was not parsed")
		}
		if p.StartedAt.Year() != 2022 || p.StartedAt.Month() != time.February || p.StartedAt.Day() != 8 {
			t.Errorf("parsed %v, want 2022-02-08", p.StartedAt)
		}
	})
	t.Run("unrecognized format yields no date", func(t *testing.T) {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
			r.RawDates.Start = "whenever it launched"
		}))
		if p.StartedAt != nil {
			t.Errorf("parsed %v from an unrecognized date", p.StartedAt)
		}
		// Age must fall back to first observation rather than the epoch.
		age, basis := p.Age(fixedNow)
		if basis != domain.AgeFromFirstSeen {
			t.Errorf("age basis = %s, want it to fall back to first seen", basis)
		}
		if age > time.Hour {
			t.Errorf("age = %v, want it derived from first observation", age)
		}
	})
}

// TestMoneyParsing verifies bounty values are parsed, and that an unparseable
// value yields nothing rather than zero, because a zero bounty and an unreadable
// one are different facts.
func TestMoneyParsing(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"1500.0", 1500},
		{"$1,500", 1500},
		{"5000", 5000},
		{"25000.00", 25000},
	}
	for _, tc := range cases {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.MaxBountyRaw = tc.in }))
		if p.MaxBountyUSD == nil {
			t.Errorf("%q did not parse", tc.in)
			continue
		}
		if *p.MaxBountyUSD != tc.want {
			t.Errorf("%q parsed as %v, want %v", tc.in, *p.MaxBountyUSD, tc.want)
		}
	}
	for _, in := range []string{"a lot", "", "unknown", "-"} {
		p := normalizeWith(baseRaw(func(r *domain.RawProgram) { r.MaxBountyRaw = in }))
		if p.MaxBountyUSD != nil {
			t.Errorf("%q became %v, want nil", in, *p.MaxBountyUSD)
		}
	}
}

// TestCryptoExchangeIsClassifiedAsPlatform is the mandate's central
// requirement: a crypto business with web and API surface is ordinary software
// work.
func TestCryptoExchangeIsClassifiedAsPlatform(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.ProjectTypesRaw = []string{"CEX"}
		r.Description = "A cryptocurrency exchange offering trading, deposits and withdrawals."
		r.Scopes = []domain.RawScope{
			{Title: "Web", Target: "*.example.com"},
			{Title: "API", Target: "https://api.example.com"},
		}
	}))
	if p.CryptoKind != domain.CryptoPlatform {
		t.Errorf("crypto kind = %s, want crypto_platform", p.CryptoKind)
	}
	if !p.CryptoTraits.Has(string(domain.CryptoTraitExchange)) {
		t.Errorf("traits = %v, want exchange to be detected", p.CryptoTraits)
	}
	if !p.CryptoTraits.Has(string(domain.CryptoTraitAPI)) {
		t.Errorf("traits = %v, want an API trait", p.CryptoTraits)
	}
	if p.CryptoTraits.Has(string(domain.CryptoTraitSmartContract)) {
		t.Errorf("traits = %v, a web/API exchange must not be tagged as smart-contract research", p.CryptoTraits)
	}
}

// TestSmartContractProgramIsClassifiedSeparately verifies pure on-chain research
// is distinguished from a crypto business.
func TestSmartContractProgramIsClassifiedSeparately(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.ProjectTypesRaw = []string{"DeFi"}
		r.CategoriesRaw = []string{"smart contract"}
		r.Description = "Security research on the staking protocol and its contracts."
		r.Scopes = []domain.RawScope{
			{Title: "Smart Contract", Target: "https://github.com/x/y/blob/main/Stake.sol"},
			{Title: "Smart Contract", Target: "https://github.com/x/y/blob/main/Rewards.sol"},
		}
	}))
	if p.CryptoKind != domain.CryptoSmartContract {
		t.Errorf("crypto kind = %s, want smart_contract_only", p.CryptoKind)
	}
	if !p.CryptoTraits.Has(string(domain.CryptoTraitSmartContract)) {
		t.Errorf("traits = %v, want smart_contract_only", p.CryptoTraits)
	}
	if p.CryptoTraits.Has(string(domain.CryptoTraitAPI)) || p.CryptoTraits.Has(string(domain.CryptoTraitWebApp)) {
		t.Errorf("traits = %v, a contract-only program must not gain platform traits", p.CryptoTraits)
	}
}

// TestOutOfScopeTargetsDoNotInfluenceClassification verifies excluded assets
// remain available as source data but cannot make a program appear to have an
// in-scope surface or crypto trait.
func TestOutOfScopeTargetsDoNotInfluenceClassification(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.ProjectTypesRaw = nil
		r.CategoriesRaw = nil
		r.Description = ""
		r.Scopes = []domain.RawScope{{
			Title: "Smart Contract", Target: "contracts/Stake.sol", OutOfScope: true,
		}}
	}))

	if len(p.Targets) != 1 || p.Targets[0].InScope {
		t.Fatalf("out-of-scope source target was not retained as excluded data: %+v", p.Targets)
	}
	if len(p.SurfaceTags) != 0 {
		t.Errorf("surface tags = %v, want no in-scope surfaces", p.SurfaceTags)
	}
	if p.CryptoKind != domain.CryptoNotCrypto || len(p.CryptoTraits) != 0 {
		t.Errorf("crypto classification = %s %v, want non-crypto with no traits", p.CryptoKind, p.CryptoTraits)
	}
}

// TestProseAloneDoesNotCreatePlatformCharacter verifies marketing copy mentioning
// web3 cannot promote a contract program to a crypto platform.
//
// This is the failure mode that would flood the channel with exactly the programs
// the profile excludes, so it is pinned directly.
func TestProseAloneDoesNotCreatePlatformCharacter(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.ProjectTypesRaw = []string{"DeFi"}
		r.CategoriesRaw = []string{"smart contract"}
		// The prose is full of web-platform vocabulary, but the scope is
		// contracts only.
		r.Description = "Our web3 ecosystem includes a web app, REST API, mobile app and backend services."
		r.Scopes = []domain.RawScope{
			{Title: "Smart Contract", Target: "https://github.com/x/y/blob/main/Stake.sol"},
		}
	}))
	if p.CryptoKind == domain.CryptoPlatform {
		t.Errorf("crypto kind = %s; prose must not override contract-only scope", p.CryptoKind)
	}
}

// TestNonCryptoProgramIsNotCryptoClassified verifies an ordinary program is not
// tagged crypto.
func TestNonCryptoProgramIsNotCryptoClassified(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.ProjectTypesRaw = []string{"SaaS"}
		r.Description = "A document management system for enterprises."
	}))
	if p.CryptoKind != domain.CryptoNotCrypto {
		t.Errorf("crypto kind = %s, want not_crypto", p.CryptoKind)
	}
	if len(p.CryptoTraits) != 0 {
		t.Errorf("traits = %v, want none", p.CryptoTraits)
	}
}

// TestSurfaceTagsCoverProfileVocabulary verifies the profile's surface names are
// produced, including the alternative web spelling.
func TestSurfaceTagsCoverProfileVocabulary(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.Scopes = []domain.RawScope{
			{Title: "Web", Target: "*.example.com"},
			{Title: "API", Target: "https://api.example.com"},
			{Title: "Repository", Target: "https://github.com/x/y"},
		}
	}))
	for _, want := range []string{"web_application", "web2", "api", "codebase"} {
		if !p.SurfaceTags.Has(want) {
			t.Errorf("surface tags = %v, want %s", p.SurfaceTags, want)
		}
	}
}

// TestCapabilityTagsAreInferredFromScope verifies attack-surface characteristics
// are read from the program's own text.
func TestCapabilityTagsAreInferredFromScope(t *testing.T) {
	p := normalizeWith(baseRaw(func(r *domain.RawProgram) {
		r.Scopes = []domain.RawScope{
			{Title: "Web", Target: "*.example.com", Description: "login and password reset flows"},
			{Title: "API", Target: "https://api.example.com", Description: "withdrawal and payment endpoints"},
		}
	}))
	for _, want := range []string{"authentication", "payments"} {
		if !p.CapabilityTags.Has(want) {
			t.Errorf("capabilities = %v, want %s", p.CapabilityTags, want)
		}
	}
}

// TestNormalizationIsDeterministic verifies repeated normalization of the same
// input is byte-identical, which is what makes stored state stable.
func TestNormalizationIsDeterministic(t *testing.T) {
	raw := baseRaw(func(r *domain.RawProgram) {
		r.Scopes = append(r.Scopes,
			domain.RawScope{Title: "Repository", Target: "https://github.com/x/y"},
			domain.RawScope{Title: "API", Target: "https://api-v2.example.com"},
			domain.RawScope{Title: "Cloud", Target: "aws://example"},
		)
	})
	first := normalizeWith(raw)
	for i := 0; i < 10; i++ {
		again := normalizeWith(raw)
		if again.ScopeFingerprint != first.ScopeFingerprint ||
			again.MetadataFingerprint != first.MetadataFingerprint ||
			again.RequirementFingerprint != first.RequirementFingerprint {
			t.Fatalf("normalization %d produced different fingerprints", i)
		}
		if !again.SurfaceTags.Equal(first.SurfaceTags) {
			t.Fatalf("normalization %d produced different surface tags", i)
		}
	}
}
