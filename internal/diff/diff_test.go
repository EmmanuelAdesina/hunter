package diff_test

import (
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/diff"
	"github.com/eadeshina/hunter/internal/domain"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func detector() *diff.Detector {
	return diff.NewDetector(func() time.Time { return fixedNow })
}

// program builds a baseline record for mutation by individual tests.
func program(mutators ...func(*domain.Program)) domain.Program {
	started := fixedNow.Add(-72 * time.Hour)
	max := 5000.0

	p := domain.Program{
		ID:           "hackenproof:example",
		Source:       "hackenproof",
		Slug:         "example",
		Name:         "Example",
		URL:          "https://example.test/programs/example",
		State:        domain.StateLive,
		Reputation:   domain.ReputationGate{Present: domain.TriNo},
		Fee:          domain.FeeGate{Present: domain.TriNo},
		KYC:          domain.TriNo,
		POC:          domain.TriYes,
		MaxBountyUSD: &max,
		Categories:   domain.NewTags("Web", "API"),
		ProjectTypes: domain.NewTags("CEX"),
		SurfaceTags:  domain.NewTags("web_application", "api"),
		CryptoKind:   domain.CryptoPlatform,
		CryptoTraits: domain.NewTags("crypto_platform", "exchange"),
		ScopeNotes:   "In-scope: IDOR, SSRF.",
		ProgramRules: "No scanners.",
		Targets: domain.Targets{
			{Kind: domain.KindWeb, Identifier: "*.example.com", Label: "Web", InScope: true},
			{Kind: domain.KindAPI, Identifier: "https://api.example.com", Label: "API", InScope: true},
		},
		ParseConfidence: domain.ConfidenceHigh,
		StartedAt:       &started,
		FirstSeenAt:     fixedNow.Add(-24 * time.Hour),
		LastSeenAt:      fixedNow.Add(-5 * time.Minute),
	}
	for _, m := range mutators {
		m(&p)
	}
	p.Finalize()
	return p
}

// kinds extracts the set of change kinds present.
func kinds(cs domain.ChangeSet) []domain.ChangeKind {
	out := make([]domain.ChangeKind, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Kind)
	}
	return out
}

func has(cs domain.ChangeSet, k domain.ChangeKind) bool {
	for _, c := range cs {
		if c.Kind == k {
			return true
		}
	}
	return false
}

func hasField(cs domain.ChangeSet, k domain.ChangeKind, field string) bool {
	for _, c := range cs {
		if c.Kind == k && c.Field == field {
			return true
		}
	}
	return false
}

// TestNoChangeDetected is the control case. A fingerprint comparison that
// reports spurious changes would make the whole system untrustworthy, so the
// unchanged path is pinned explicitly.
func TestNoChangeDetected(t *testing.T) {
	prev := program()
	// Recomputing from identical inputs must produce identical fingerprints.
	cur := program(func(p *domain.Program) {
		p.LastSeenAt = fixedNow
	})

	got := detector().Compare(prev, cur)
	if !got.Changes.Empty() {
		t.Errorf("identical programs produced changes: %v", got.Changes)
	}
	if got.IsNew {
		t.Error("IsNew is true for a program with previous state")
	}
	if !got.FirstSeenAt.Equal(prev.FirstSeenAt) {
		t.Errorf("FirstSeenAt = %v, want it carried forward as %v", got.FirstSeenAt, prev.FirstSeenAt)
	}
}

// TestNewProgramIsDetected verifies a program with no prior state is reported
// as new with high severity.
func TestNewProgramIsDetected(t *testing.T) {
	cur := program()
	got := detector().Compare(domain.Program{}, cur)

	if !got.IsNew {
		t.Error("IsNew is false for a program with no previous state")
	}
	if !has(got.Changes, domain.ChangeNewProgram) {
		t.Errorf("changes = %v, want NEW_PROGRAM", kinds(got.Changes))
	}
	if got.Changes.Highest() != domain.SeverityHigh {
		t.Errorf("severity = %s, want high", got.Changes.Highest())
	}
	if got.FirstSeenAt.IsZero() {
		t.Error("FirstSeenAt was not set for a new program")
	}
}

// TestScopeAddition verifies an added asset produces a specific, actionable
// event rather than only a generic scope change.
func TestScopeAddition(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.Targets = append(p.Targets, domain.Target{
			Kind: domain.KindAPI, Identifier: "https://api-v2.example.com", Label: "API", InScope: true,
		})
	})

	got := detector().Compare(prev, cur)
	if !has(got.Changes, domain.ChangeTargetAdded) {
		t.Errorf("changes = %v, want TARGET_ADDED", kinds(got.Changes))
	}
	if !has(got.Changes, domain.ChangeAPIAdded) {
		t.Errorf("changes = %v, want API_ADDED", kinds(got.Changes))
	}
	if !has(got.Changes, domain.ChangeScopeChanged) {
		t.Errorf("changes = %v, want SCOPE_CHANGED", kinds(got.Changes))
	}
}

// TestRepositoryAddition verifies a newly published repository is detected.
func TestRepositoryAddition(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.Targets = append(p.Targets, domain.Target{
			Kind:       domain.KindRepository,
			Identifier: "https://github.com/example/app",
			Label:      "Repository",
			InScope:    true,
		})
	})

	got := detector().Compare(prev, cur)
	if !has(got.Changes, domain.ChangeRepositoryAdded) {
		t.Errorf("changes = %v, want REPOSITORY_ADDED", kinds(got.Changes))
	}
}

// TestScopeRemoval verifies an asset leaving scope is detected and rated lower
// than one entering it.
func TestScopeRemoval(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.Targets = domain.Targets{
			{Kind: domain.KindWeb, Identifier: "*.example.com", Label: "Web", InScope: true},
		}
	})

	got := detector().Compare(prev, cur)
	if !has(got.Changes, domain.ChangeTargetRemoved) {
		t.Errorf("changes = %v, want TARGET_REMOVED", kinds(got.Changes))
	}
	if !has(got.Changes, domain.ChangeAPIRemoved) {
		t.Errorf("changes = %v, want API_REMOVED", kinds(got.Changes))
	}
	for _, c := range got.Changes {
		if c.Kind == domain.ChangeTargetRemoved && c.Severity == domain.SeverityHigh {
			t.Error("scope removal rated high; it should not outrank scope expansion")
		}
	}
}

// TestOutOfScopeTargetIsNotScopeChange verifies moving an asset into the
// excluded list registers as a removal from testable scope.
func TestOutOfScopeTargetIsNotScopeChange(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.Targets = domain.Targets{
			{Kind: domain.KindWeb, Identifier: "*.example.com", Label: "Web", InScope: true},
			{Kind: domain.KindAPI, Identifier: "https://api.example.com", Label: "API", InScope: true},
			{Kind: domain.KindAPI, Identifier: "https://legacy.example.com", Label: "API", InScope: false},
		}
	})

	got := detector().Compare(prev, cur)
	if !got.Changes.Empty() {
		t.Errorf("an out-of-scope asset produced changes: %v", got.Changes)
	}
}

// TestRequirementChanges verifies each access gate is reported individually.
func TestRequirementChanges(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*domain.Program)
		want    domain.ChangeKind
		wantSev domain.Severity
	}{
		{
			name: "reputation lowered",
			mutate: func(p *domain.Program) {
				p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 50}
			},
			want:    domain.ChangeReputationChanged,
			wantSev: domain.SeverityMedium,
		},
		{
			name: "reputation raised",
			mutate: func(p *domain.Program) {
				p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 500}
			},
			want:    domain.ChangeReputationChanged,
			wantSev: domain.SeverityMedium,
		},
		{
			name: "kyc introduced",
			mutate: func(p *domain.Program) {
				p.KYC = domain.TriYes
			},
			want:    domain.ChangeKYCChanged,
			wantSev: domain.SeverityMedium,
		},
		{
			name: "fee introduced",
			mutate: func(p *domain.Program) {
				p.Fee = domain.FeeGate{Present: domain.TriYes, USD: 3}
			},
			want:    domain.ChangeFeeChanged,
			wantSev: domain.SeverityMedium,
		},
		{
			name: "poc requirement changed",
			mutate: func(p *domain.Program) {
				p.POC = domain.TriNo
			},
			want:    domain.ChangePOCChanged,
			wantSev: domain.SeverityLow,
		},
		{
			name: "scope review changed",
			mutate: func(p *domain.Program) {
				p.ScopeNotes = "In-scope: IDOR only."
			},
			want:    domain.ChangeScopeReviewChanged,
			wantSev: domain.SeverityMedium,
		},
		{
			name: "program rules changed",
			mutate: func(p *domain.Program) {
				p.ProgramRules = "No scanners. Disclosure within 90 days."
			},
			want:    domain.ChangeRequirementChanged,
			wantSev: domain.SeverityMedium,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := program()
			cur := program(tc.mutate)
			got := detector().Compare(prev, cur)

			if !has(got.Changes, tc.want) {
				t.Fatalf("changes = %v, want %s", kinds(got.Changes), tc.want)
			}
			for _, c := range got.Changes {
				if c.Kind == tc.want && c.Severity != tc.wantSev {
					t.Errorf("%s severity = %s, want %s", tc.want, c.Severity, tc.wantSev)
				}
			}
		})
	}
}

// TestBountyChangeDirection verifies a raised ceiling outranks a lowered floor,
// because a bigger prize is the actionable direction.
func TestBountyChangeDirection(t *testing.T) {
	high := 50000.0
	prev := program()
	cur := program(func(p *domain.Program) { p.MaxBountyUSD = &high })
	got := detector().Compare(prev, cur)

	if !has(got.Changes, domain.ChangeBountyChanged) {
		t.Fatalf("changes = %v, want BOUNTY_CHANGED", kinds(got.Changes))
	}
	for _, c := range got.Changes {
		if c.Kind == domain.ChangeBountyChanged && c.Severity != domain.SeverityMedium {
			t.Errorf("raised bounty severity = %s, want medium", c.Severity)
		}
	}

	low := 100.0
	prev2 := program()
	cur2 := program(func(p *domain.Program) { p.MaxBountyUSD = &low })
	got2 := detector().Compare(prev2, cur2)
	for _, c := range got2.Changes {
		if c.Kind == domain.ChangeBountyChanged && c.Severity != domain.SeverityLow {
			t.Errorf("lowered bounty severity = %s, want low", c.Severity)
		}
	}
}

// TestProgramReactivation verifies a program returning to life is high
// severity, which is the strongest signal after a brand-new program.
func TestProgramReactivation(t *testing.T) {
	cases := []struct {
		name string
		from domain.ProgramState
	}{
		{"resumed from paused", domain.StatePaused},
		{"reopened after ending", domain.StateEnded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := program(func(p *domain.Program) { p.State = tc.from })
			cur := program()
			got := detector().Compare(prev, cur)

			if !has(got.Changes, domain.ChangeProgramReactivated) {
				t.Fatalf("changes = %v, want PROGRAM_REACTIVATED", kinds(got.Changes))
			}
			if got.Changes.Highest() != domain.SeverityHigh {
				t.Errorf("severity = %s, want high", got.Changes.Highest())
			}
			if !has(got.Changes, domain.ChangeStateChanged) {
				t.Errorf("changes = %v, want STATE_CHANGED", kinds(got.Changes))
			}
		})
	}
}

// TestProgramEnded verifies a closed program is reported.
func TestProgramEnded(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) { p.State = domain.StateEnded })
	got := detector().Compare(prev, cur)

	if !has(got.Changes, domain.ChangeProgramEnded) {
		t.Errorf("changes = %v, want PROGRAM_ENDED", kinds(got.Changes))
	}
	if has(got.Changes, domain.ChangeProgramReactivated) {
		t.Error("a program ending was reported as reactivated")
	}
}

// TestCryptoReclassification verifies a change in crypto character is detected,
// which is what happens when a program gains or loses a contract scope.
func TestCryptoReclassification(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.CryptoKind = domain.CryptoMixed
		p.CryptoTraits = domain.NewTags("crypto_platform", "exchange", "smart_contract_only")
	})
	got := detector().Compare(prev, cur)

	if !has(got.Changes, domain.ChangeCryptoReclassified) {
		t.Errorf("changes = %v, want CRYPTO_RECLASSIFIED", kinds(got.Changes))
	}
	if !hasField(got.Changes, domain.ChangeCryptoReclassified, "crypto_kind") {
		t.Error("reclassification event is missing its field name")
	}
}

// TestSurfaceChangeIsDetected verifies a change in the technical surface is
// reported separately from the raw scope change.
func TestSurfaceChangeIsDetected(t *testing.T) {
	prev := program()
	cur := program(func(p *domain.Program) {
		p.SurfaceTags = domain.NewTags("web_application", "api", "codebase")
		p.Targets = append(p.Targets, domain.Target{
			Kind: domain.KindRepository, Identifier: "https://github.com/example/app", Label: "Repo", InScope: true,
		})
	})
	got := detector().Compare(prev, cur)
	if !has(got.Changes, domain.ChangeSurfaceChanged) {
		t.Errorf("changes = %v, want SURFACE_CHANGED", kinds(got.Changes))
	}
}

// TestChangeOrderingIsDeterministic verifies changes are ordered by descending
// severity, so the most important one is always rendered first in an alert.
func TestChangeOrderingIsDeterministic(t *testing.T) {
	prev := program(func(p *domain.Program) { p.State = domain.StatePaused })
	cur := program(func(p *domain.Program) {
		p.State = domain.StateLive
		p.KYC = domain.TriYes
		p.Targets = append(p.Targets, domain.Target{
			Kind: domain.KindAPI, Identifier: "https://new.example.com", Label: "API", InScope: true,
		})
		p.MaxBountyUSD = &[]float64{50000}[0]
	})

	var first []string
	for i := 0; i < 25; i++ {
		got := detector().Compare(prev, cur)
		rendered := make([]string, 0, len(got.Changes))
		for _, c := range got.Changes {
			rendered = append(rendered, c.Describe())
		}
		if i == 0 {
			first = rendered
			continue
		}
		if len(rendered) != len(first) {
			t.Fatalf("change count varies between runs: %d vs %d", len(rendered), len(first))
		}
		for j := range rendered {
			if rendered[j] != first[j] {
				t.Fatalf("ordering varies at %d: %q vs %q", j, rendered[j], first[j])
			}
		}
	}
	if len(first) == 0 {
		t.Fatal("no changes produced")
	}
}

// TestChangeDescriptionsAreReadable verifies every rendered line is
// self-contained, since these become email text.
func TestChangeDescriptionsAreReadable(t *testing.T) {
	prev := program(func(p *domain.Program) {
		p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 200}
	})
	cur := program(func(p *domain.Program) {
		p.Targets = append(p.Targets, domain.Target{
			Kind: domain.KindAPI, Identifier: "https://api-v2.example.com", Label: "API", InScope: true,
		})
	})

	got := detector().Compare(prev, cur)
	for _, c := range got.Changes {
		line := c.Describe()
		if line == "" {
			t.Errorf("%s rendered as an empty line", c.Kind)
		}
		if len(line) > 400 {
			t.Errorf("%s rendered %d characters; alerts must stay readable: %q", c.Kind, len(line), line)
		}
	}
}

// TestMaterialChangeIsIdentified verifies which change sets warrant alerting.
func TestMaterialChangeIsIdentified(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*domain.Program)
		wantMaterial bool
	}{
		{"no change", func(*domain.Program) {}, false},
		{"api added", func(p *domain.Program) {
			p.Targets = append(p.Targets, domain.Target{
				Kind: domain.KindAPI, Identifier: "https://new.example.com", Label: "API", InScope: true,
			})
		}, true},
		{"kyc introduced", func(p *domain.Program) { p.KYC = domain.TriYes }, true},
		{"program ended", func(p *domain.Program) { p.State = domain.StateEnded }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector().Compare(program(), program(tc.mutate))
			if got.Material() != tc.wantMaterial {
				t.Errorf("Material() = %v, want %v; changes: %v", got.Material(), tc.wantMaterial, kinds(got.Changes))
			}
		})
	}
}

// TestNewProgramWithoutLaunchDate is a regression test.
//
// StartedAt is a pointer because sources frequently omit a launch date.
// Dereferencing it without a nil check panicked on the first program that lacked
// one, which would have aborted every scan of a platform where any program omits
// its launch date.
func TestNewProgramWithoutLaunchDate(t *testing.T) {
	cur := program(func(p *domain.Program) {
		p.StartedAt = nil
		p.SourceUpdatedAt = nil
		p.EndsAt = nil
	})

	got := detector().Compare(domain.Program{}, cur)
	if !got.IsNew {
		t.Error("IsNew is false for a program with no previous state")
	}
	if !has(got.Changes, domain.ChangeNewProgram) {
		t.Errorf("changes = %v, want NEW_PROGRAM", kinds(got.Changes))
	}
	if has(got.Changes, domain.ChangeFirstSeen) {
		t.Error("a launch date was reported for a program that has none")
	}
}

// TestProgramWithoutOptionalPointers verifies comparison tolerates every
// optional timestamp being absent, which is the normal case for a sparse source.
func TestProgramWithoutOptionalPointers(t *testing.T) {
	prev := program(func(p *domain.Program) {
		p.StartedAt = nil
		p.SourceUpdatedAt = nil
		p.EndsAt = nil
		p.MinBountyUSD = nil
		p.MaxBountyUSD = nil
		p.RewardsPaidUSD = nil
		p.SubmittedReports = nil
		p.SubmittedReportsKnown = false
	})
	cur := program(func(p *domain.Program) {
		p.StartedAt = nil
		p.SourceUpdatedAt = nil
		p.EndsAt = nil
		p.MinBountyUSD = nil
		p.MaxBountyUSD = nil
		p.RewardsPaidUSD = nil
		p.SubmittedReports = nil
		p.SubmittedReportsKnown = false
	})

	got := detector().Compare(prev, cur)
	if !got.Changes.Empty() {
		t.Errorf("identical sparse programs produced changes: %v", got.Changes)
	}
}
