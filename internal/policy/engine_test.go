package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/policy"
)

// fixedNow keeps decisions reproducible regardless of wall-clock time.
var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// loadProfile parses a profile from YAML text, applying defaults.
func loadProfile(t *testing.T, yaml string) *config.Profile {
	t.Helper()
	p, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	return p
}

// baseProfile mirrors the researcher's stated constraints.
const baseProfile = `
profile:
  name: test
  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
    accept_unknown_access_gates: false
    accept_unknown_parse_state: false
  target_domains:
    included: [web_application, api, backend, codebase]
  crypto:
    enabled: true
    mode: auto
    require_allowed_trait: true
    allowed: [crypto_platform, exchange, wallet_platform, crypto_api, crypto_backend]
    excluded: [smart_contract_only, solidity_only, protocol_consensus, blockchain_core_protocol]
    dominance_ratio: 0.6
  program_states:
    allowed: [live, new]
  notifications:
    enabled: true
    min_severity: medium
    alert_on_new_programs: true
`

// programOption mutates a base program so that each test varies one dimension.
type programOption func(*domain.Program)

// newProgram builds a fully eligible program that individual checks then perturb.
func newProgram(opts ...programOption) domain.Program {
	started := fixedNow.Add(-48 * time.Hour)
	max := 5000.0
	now := fixedNow

	p := domain.Program{
		ID:                    "hackenproof:example",
		Source:                "hackenproof",
		Slug:                  "example",
		Name:                  "Example Exchange",
		URL:                   "https://example.test/programs/example",
		State:                 domain.StateLive,
		Reputation:            domain.ReputationGate{Present: domain.TriNo},
		Fee:                   domain.FeeGate{Present: domain.TriNo},
		KYC:                   domain.TriNo,
		POC:                   domain.TriYes,
		MinBountyUSD:          &[]float64{100}[0],
		MaxBountyUSD:          &max,
		SubmittedReports:      &[]int{7}[0],
		SubmittedReportsKnown: true,
		Categories:            domain.NewTags("Web", "API"),
		ProjectTypes:          domain.NewTags("CEX"),
		SurfaceTags:           domain.NewTags("web_application", "api"),
		CapabilityTags:        domain.NewTags("authentication", "user_accounts"),
		Targets: domain.Targets{
			{Kind: domain.KindWeb, Identifier: "*.example.com", Label: "Web", InScope: true},
			{Kind: domain.KindAPI, Identifier: "https://api.example.com", Label: "API", InScope: true},
		},
		ParseConfidence: domain.ConfidenceHigh,
		CryptoKind:      domain.CryptoPlatform,
		CryptoTraits:    domain.NewTags("crypto_platform", "exchange", "crypto_api"),
		StartedAt:       &started,
		FirstSeenAt:     now.Add(-30 * time.Minute),
		LastSeenAt:      now,
	}
	for _, o := range opts {
		o(&p)
	}
	p.Finalize()
	return p
}

// decide evaluates a program and returns the decision.
func decide(t *testing.T, yaml string, p domain.Program) domain.EligibilityDecision {
	t.Helper()
	return policy.New(loadProfile(t, yaml), func() time.Time { return fixedNow }).Evaluate(p)
}

// TestBaselineEligible establishes the reference case: a crypto exchange with
// web and API scope, no access gates, is exactly what the profile describes.
func TestBaselineEligible(t *testing.T) {
	d := decide(t, baseProfile, newProgram())
	if !d.Eligible {
		t.Fatalf("baseline program rejected: %s", strings.Join(d.Reasons, " ; "))
	}
	if len(d.Blockers) != 0 {
		t.Errorf("blockers = %+v, want none", d.Blockers)
	}
}

// TestAccessGates covers the three access requirements independently.
func TestAccessGates(t *testing.T) {
	cases := []struct {
		name     string
		opt      programOption
		wantPass bool
		checkID  string
	}{
		{
			name:     "reputation under the ceiling passes",
			opt:      func(p *domain.Program) { p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 50} },
			wantPass: true,
			checkID:  policy.CheckReputation,
		},
		{
			name:     "reputation exactly at the ceiling passes",
			opt:      func(p *domain.Program) { p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 80} },
			wantPass: true,
			checkID:  policy.CheckReputation,
		},
		{
			name:     "reputation above the ceiling fails",
			opt:      func(p *domain.Program) { p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 150} },
			wantPass: false,
			checkID:  policy.CheckReputation,
		},
		{
			name:     "unknown reputation blocks",
			opt:      func(p *domain.Program) { p.Reputation = domain.ReputationGate{Present: domain.TriUnknown} },
			wantPass: false,
			checkID:  policy.CheckReputation,
		},
		{
			name:     "fee under the ceiling passes",
			opt:      func(p *domain.Program) { p.Fee = domain.FeeGate{Present: domain.TriYes, USD: 5} },
			wantPass: true,
			checkID:  policy.CheckSubmissionFee,
		},
		{
			name:     "fee above the ceiling fails",
			opt:      func(p *domain.Program) { p.Fee = domain.FeeGate{Present: domain.TriYes, USD: 25} },
			wantPass: false,
			checkID:  policy.CheckSubmissionFee,
		},
		{
			name:     "unknown fee blocks",
			opt:      func(p *domain.Program) { p.Fee = domain.FeeGate{Present: domain.TriUnknown} },
			wantPass: false,
			checkID:  policy.CheckSubmissionFee,
		},
		{
			name:     "no KYC passes",
			opt:      func(p *domain.Program) { p.KYC = domain.TriNo },
			wantPass: true,
			checkID:  policy.CheckKYC,
		},
		{
			name:     "required KYC fails",
			opt:      func(p *domain.Program) { p.KYC = domain.TriYes },
			wantPass: false,
			checkID:  policy.CheckKYC,
		},
		{
			name:     "unknown KYC blocks",
			opt:      func(p *domain.Program) { p.KYC = domain.TriUnknown },
			wantPass: false,
			checkID:  policy.CheckKYC,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(t, baseProfile, newProgram(tc.opt))
			check, ok := d.CheckByID(tc.checkID)
			if !ok {
				t.Fatalf("check %q missing; got %v", tc.checkID, checkIDs(d))
			}
			gotPass := check.Outcome == domain.CheckPass
			if gotPass != tc.wantPass {
				t.Errorf("%s outcome = %s, want pass=%v (%s)", tc.checkID, check.Outcome, tc.wantPass, check.Detail)
			}
			if d.Eligible != tc.wantPass {
				t.Errorf("eligible = %v, want %v; reasons: %v", d.Eligible, tc.wantPass, d.Reasons)
			}
		})
	}
}

// TestKYCProfileOverride verifies that changing the stance is configuration,
// not code. This is the promise the mandate makes about kyc_required.
func TestKYCProfileOverride(t *testing.T) {
	profile := strings.Replace(baseProfile, "kyc_required: no", "kyc_required: yes", 1)
	d := decide(t, profile, newProgram(func(p *domain.Program) { p.KYC = domain.TriYes }))
	if !d.Eligible {
		t.Errorf("KYC-requiring program rejected under kyc_required: yes: %v", d.Reasons)
	}
}

// TestReputationCeilingIsConfiguration verifies the ceiling can be raised
// without touching code.
func TestReputationCeilingIsConfiguration(t *testing.T) {
	profile := strings.Replace(baseProfile, "max_reputation_points: 80", "max_reputation_points: 200", 1)
	p := newProgram(func(p *domain.Program) {
		p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 150}
	})
	if d := decide(t, profile, p); !d.Eligible {
		t.Errorf("150-point program rejected under a 200 ceiling: %v", d.Reasons)
	}
}

// TestUnknownAcceptanceIsOptIn verifies unknowns only pass when the profile
// explicitly permits them.
func TestUnknownAcceptanceIsOptIn(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.Reputation = domain.ReputationGate{Present: domain.TriUnknown}
		p.KYC = domain.TriUnknown
		p.Fee = domain.FeeGate{Present: domain.TriUnknown}
	})

	if d := decide(t, baseProfile, p); d.Eligible {
		t.Error("a program with three unknown gates was approved by default")
	}

	profile := strings.Replace(baseProfile,
		"accept_unknown_access_gates: false", "accept_unknown_access_gates: true", 1)
	if d := decide(t, profile, p); !d.Eligible {
		t.Errorf("unknowns rejected despite opt-in: %v", d.Reasons)
	}
}

// TestLowConfidenceIsQuarantined verifies a poorly parsed record is not
// approved by default, which is what stops a parser regression from
// approving everything.
func TestLowConfidenceIsQuarantined(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.ParseConfidence = domain.ConfidenceLow
		p.ParseIssues = []string{"kycRequired missing"}
	})

	d := decide(t, baseProfile, p)
	if d.Eligible {
		t.Fatal("a low-confidence record was approved")
	}
	check, ok := d.CheckByID(policy.CheckParseTrust)
	if !ok {
		t.Fatal("parse trust check missing")
	}
	if check.Outcome != domain.CheckUnknown {
		t.Errorf("parse trust outcome = %s, want unknown", check.Outcome)
	}
	if !strings.Contains(check.Detail, "kycRequired") {
		t.Errorf("detail = %q, want it to name the parse problem", check.Detail)
	}

	profile := strings.Replace(baseProfile,
		"accept_unknown_parse_state: false", "accept_unknown_parse_state: true", 1)
	if d := decide(t, profile, p); !d.Eligible {
		t.Errorf("low-confidence record rejected despite opt-in: %v", d.Reasons)
	}
}

// TestCryptoPlatformIsRelevant is the mandate's central requirement: a crypto
// program with web and API surface must be treated as ordinary software work.
func TestCryptoPlatformIsRelevant(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.ProjectTypes = domain.NewTags("CEX")
		p.CryptoKind = domain.CryptoPlatform
		p.CryptoTraits = domain.NewTags("crypto_platform", "exchange", "crypto_api", "crypto_web_application")
	})
	d := decide(t, baseProfile, p)
	if !d.Eligible {
		t.Fatalf("crypto exchange with web/API scope rejected: %v", d.Reasons)
	}

	check, _ := d.CheckByID(policy.CheckCryptoAllowed)
	if check.Outcome != domain.CheckPass {
		t.Errorf("crypto allow check = %s, want pass", check.Outcome)
	}
}

// TestSmartContractOnlyIsExcluded verifies pure on-chain research is filtered
// out. This is the distinction that keeps a crypto alert stream useful.
func TestSmartContractOnlyIsExcluded(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.ProjectTypes = domain.NewTags("DeFi")
		p.Categories = domain.NewTags("smart contract")
		p.CryptoKind = domain.CryptoSmartContract
		p.CryptoTraits = domain.NewTags("smart_contract_only", "solidity_only")
		p.SurfaceTags = domain.NewTags("smart_contract", "protocol")
		p.Targets = domain.Targets{
			{Kind: domain.KindSmartContract, Identifier: "contracts/Stake.sol", Label: "Smart Contract", InScope: true},
		}
	})

	d := decide(t, baseProfile, p)
	if d.Eligible {
		t.Fatal("a smart-contract-only program was approved")
	}
	// It should fail for a stated reason, not merely be absent from the allow
	// list by accident.
	found := false
	for _, c := range d.Blockers {
		if c.ID == policy.CheckCryptoAllowed || c.ID == policy.CheckCryptoExcluded {
			found = true
		}
	}
	if !found {
		t.Errorf("no crypto blocker among %v", checkIDs(d))
	}
}

// TestMixedCryptoProgramUsesDominance verifies a program that is both a crypto
// platform and has a contract scope is judged on which character dominates.
//
// Rejecting a crypto exchange merely because one smart contract appears in its
// scope would be a false negative; accepting a protocol research program because
// it mentions an API would be a false positive. The dominance ratio is what
// separates them.
func TestMixedCryptoProgramUsesDominance(t *testing.T) {
	t.Run("platform dominates", func(t *testing.T) {
		p := newProgram(func(p *domain.Program) {
			p.CryptoKind = domain.CryptoMixed
			p.CryptoTraits = domain.NewTags(
				"crypto_platform", "exchange", "crypto_api", "crypto_backend",
				"smart_contract_only", "solidity_only", "protocol_consensus",
			)
		})
		if d := decide(t, baseProfile, p); !d.Eligible {
			t.Errorf("platform-dominant crypto program rejected: %v", d.Reasons)
		}
	})

	t.Run("contract dominates", func(t *testing.T) {
		p := newProgram(func(p *domain.Program) {
			p.CryptoKind = domain.CryptoSmartContract
			p.CryptoTraits = domain.NewTags("smart_contract_only", "solidity_only", "protocol_consensus")
			p.SurfaceTags = domain.NewTags("smart_contract")
			p.Targets = domain.Targets{
				{Kind: domain.KindSmartContract, Identifier: "contracts/A.sol", Label: "Smart Contract", InScope: true},
			}
		})
		if d := decide(t, baseProfile, p); d.Eligible {
			t.Error("contract-dominant crypto program approved")
		}
	})
}

// TestCryptoModeIsConfiguration verifies crypto posture is a profile setting.
func TestCryptoModeIsConfiguration(t *testing.T) {
	contractOnly := func() domain.Program {
		return newProgram(func(p *domain.Program) {
			p.CryptoKind = domain.CryptoSmartContract
			p.CryptoTraits = domain.NewTags("smart_contract_only")
			p.SurfaceTags = domain.NewTags("smart_contract")
			p.Targets = domain.Targets{
				{Kind: domain.KindSmartContract, Identifier: "A.sol", Label: "Smart Contract", InScope: true},
			}
		})
	}

	if d := decide(t, baseProfile, contractOnly()); d.Eligible {
		t.Error("contract program approved under crypto.mode: auto")
	}

	// platform_only admits the platform and rejects everything else.
	platformOnly := strings.Replace(baseProfile, "mode: auto", "mode: platform_only", 1)
	if d := decide(t, platformOnly, contractOnly()); d.Eligible {
		t.Error("contract program approved under platform_only")
	}

	// off disables crypto filtering entirely, so a smart-contract program with
	// an in-scope web surface passes.
	off := strings.Replace(baseProfile, "mode: auto", "mode: off", 1)
	passing := newProgram(func(p *domain.Program) {
		p.CryptoKind = domain.CryptoSmartContract
		p.CryptoTraits = domain.NewTags("smart_contract_only")
	})
	if d := decide(t, off, passing); !d.Eligible {
		t.Errorf("crypto filtering still applied under mode: off: %v", d.Reasons)
	}
}

// TestNonCryptoProgramIsNotCryptoFiltered verifies a non-crypto program is not
// blocked by crypto rules.
func TestNonCryptoProgramIsNotCryptoFiltered(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.ProjectTypes = domain.NewTags("SaaS")
		p.CryptoKind = domain.CryptoNotCrypto
		p.CryptoTraits = nil
	})
	if d := decide(t, baseProfile, p); !d.Eligible {
		t.Errorf("non-crypto program blocked by crypto rules: %v", d.Reasons)
	}
}

// TestSurfaceRequirement verifies the target-domain filter.
func TestSurfaceRequirement(t *testing.T) {
	t.Run("web and api pass", func(t *testing.T) {
		p := newProgram()
		if d := decide(t, baseProfile, p); !d.Eligible {
			t.Errorf("web/API program rejected: %v", d.Reasons)
		}
	})

	t.Run("smart contract only fails", func(t *testing.T) {
		p := newProgram(func(p *domain.Program) {
			p.SurfaceTags = domain.NewTags("smart_contract")
			p.Targets = domain.Targets{
				{Kind: domain.KindSmartContract, Identifier: "A.sol", Label: "Smart Contract", InScope: true},
			}
		})
		if d := decide(t, baseProfile, p); d.Eligible {
			t.Error("smart-contract-only program approved by the surface filter")
		}
	})

	t.Run("no surfaces fails", func(t *testing.T) {
		p := newProgram(func(p *domain.Program) {
			p.SurfaceTags = nil
			p.Targets = nil
		})
		if d := decide(t, baseProfile, p); d.Eligible {
			t.Error("program with no recognizable surface was approved")
		}
	})
}

// TestProgramStates verifies lifecycle filtering.
func TestProgramStates(t *testing.T) {
	cases := []struct {
		state domain.ProgramState
		want  bool
	}{
		{domain.StateLive, true},
		{domain.StateNew, true},
		{domain.StatePaused, false},
		{domain.StateEnded, false},
		{domain.StateUnlisted, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			p := newProgram(func(p *domain.Program) { p.State = tc.state })
			d := decide(t, baseProfile, p)
			if d.Eligible != tc.want {
				t.Errorf("state %s: eligible = %v, want %v (%v)", tc.state, d.Eligible, tc.want, d.Reasons)
			}
		})
	}

	t.Run("unknown state blocks", func(t *testing.T) {
		p := newProgram(func(p *domain.Program) { p.State = domain.StateUnknown })
		d := decide(t, baseProfile, p)
		if d.Eligible {
			t.Error("unknown state approved")
		}
		check, _ := d.CheckByID(policy.CheckState)
		if check.Outcome != domain.CheckUnknown {
			t.Errorf("state check = %s, want unknown", check.Outcome)
		}
	})
}

// TestDecisionsAreDeterministic verifies the engine is a pure function: the same
// inputs must produce byte-identical reasons, or recorded explanations become
// unreproducible.
func TestDecisionsAreDeterministic(t *testing.T) {
	p := newProgram(func(p *domain.Program) {
		p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 150}
		p.KYC = domain.TriYes
	})
	first := decide(t, baseProfile, p)
	for i := 0; i < 20; i++ {
		again := decide(t, baseProfile, p)
		if strings.Join(again.Reasons, "\n") != strings.Join(first.Reasons, "\n") {
			t.Fatalf("decision %d differs:\n first: %v\n again: %v", i, first.Reasons, again.Reasons)
		}
		if len(again.Checks) != len(first.Checks) {
			t.Fatalf("check count %d differs from %d", len(again.Checks), len(first.Checks))
		}
		for j := range again.Checks {
			if again.Checks[j] != first.Checks[j] {
				t.Errorf("check %d differs: %+v vs %+v", j, again.Checks[j], first.Checks[j])
			}
		}
	}
}

// TestEveryDecisionIsExplained verifies a decision always carries reasons,
// including for rejections.
func TestEveryDecisionIsExplained(t *testing.T) {
	for _, p := range []domain.Program{
		newProgram(),
		newProgram(func(p *domain.Program) { p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 999} }),
		newProgram(func(p *domain.Program) { p.State = domain.StateUnknown }),
		newProgram(func(p *domain.Program) { p.ParseConfidence = domain.ConfidenceLow }),
	} {
		d := decide(t, baseProfile, p)
		if len(d.Reasons) == 0 {
			t.Errorf("decision for %s carries no reasons", p.Name)
		}
		if len(d.Checks) == 0 {
			t.Errorf("decision for %s carries no checks", p.Name)
		}
		for _, r := range d.Reasons {
			if strings.TrimSpace(r) == "" {
				t.Errorf("blank reason in %v", d.Reasons)
			}
		}
	}
}

// TestUnknownsAreDistinctFromFailures verifies an unparsed fact is reported as
// unknown rather than as a violation, so a human can tell the two apart.
func TestUnknownsAreDistinctFromFailures(t *testing.T) {
	p := newProgram(func(p *domain.Program) { p.KYC = domain.TriUnknown })
	d := decide(t, baseProfile, p)

	check, ok := d.CheckByID(policy.CheckKYC)
	if !ok {
		t.Fatal("KYC check missing")
	}
	if check.Outcome != domain.CheckUnknown {
		t.Fatalf("outcome = %s, want unknown", check.Outcome)
	}
	if check.Observed != "" {
		t.Errorf("unknown check carries observed value %q; it should not assert a fact", check.Observed)
	}
	if !strings.Contains(check.Reason(), "unknown") {
		t.Errorf("reason = %q, want it to say the fact is unknown", check.Reason())
	}
}

// checkIDs lists the identifiers present in a decision, for failure messages.
func checkIDs(d domain.EligibilityDecision) []string {
	out := make([]string, 0, len(d.Checks))
	for _, c := range d.Checks {
		out = append(out, string(c.Outcome)+":"+c.ID)
	}
	return out
}
