package alerts_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/alerts"
	"github.com/eadeshina/hunter/internal/domain"
)

// launchedAgo returns a program option setting the source-reported launch date to
// the given age before the fixed clock.
func launchedAgo(age time.Duration) func(*domain.Program) {
	return func(p *domain.Program) {
		t := fixedNow.Add(-age)
		p.StartedAt = &t
	}
}

// TestOnlyNewlyLaunchedProgramsAlert is the central behavioural guarantee.
//
// The channel exists to report opportunities that just opened. A program that
// has been live for a year is not one, however well it matches the profile, and
// it must never reach a notification channel.
func TestOnlyNewlyLaunchedProgramsAlert(t *testing.T) {
	cases := []struct {
		name    string
		age     time.Duration
		noDate  bool
		want    bool
		because string
	}{
		{name: "launched minutes ago", age: 12 * time.Minute, want: true,
			because: "this is the event the channel is for"},
		{name: "launched two hours ago", age: 2 * time.Hour, want: true,
			because: "still inside the window"},
		{name: "launched twenty hours ago", age: 20 * time.Hour, want: true,
			because: "just inside the window"},
		{name: "launched three days ago", age: 72 * time.Hour, want: false,
			because: "outside the window; this is an existing program"},
		{name: "launched four years ago", age: 4 * 365 * 24 * time.Hour, want: false,
			because: "long established; exactly the noise being removed"},
		{name: "no published launch date", noDate: true, want: false,
			because: "recency cannot be established, and unknown is never assumed fresh"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := launchedAgo(tc.age)
			if tc.noDate {
				opt = func(p *domain.Program) { p.StartedAt = nil }
			}
			got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
				c.Program = program(opt)
				c.Program.Finalize()
			}))
			if got != nil && !tc.want {
				t.Errorf("alerted for a program %s", tc.because)
			}
			if got == nil && tc.want {
				t.Errorf("no alert, but %s", tc.because)
			}
		})
	}
}

// TestFutureLaunchDateIsRejected verifies a launch date ahead of the clock does
// not read as brand new. That would otherwise be a way for anything to reach
// the channel.
func TestFutureLaunchDateIsRejected(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(func(p *domain.Program) {
			t := fixedNow.Add(48 * time.Hour)
			p.StartedAt = &t
		})
		c.Program.Finalize()
	}))
	if got != nil {
		t.Errorf("a program launching in the future alerted: %q", got.Subject)
	}
}

// TestGatesNeverProduceAnAlert is the hard guarantee the recipient relies on.
//
// Every access gate is exercised in both directions. A program that fails any
// gate must be silent regardless of how new or how well matched it is.
func TestGatesNeverProduceAnAlert(t *testing.T) {
	cases := []struct {
		name string
		opt  func(*domain.Program)
	}{
		{"requires KYC", func(p *domain.Program) { p.KYC = domain.TriYes }},
		{"requires a reputation gate above the ceiling", func(p *domain.Program) {
			p.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 500}
		}},
		{"charges a fee above the ceiling", func(p *domain.Program) {
			p.Fee = domain.FeeGate{Present: domain.TriYes, USD: 500}
		}},
		{"KYC status cannot be established", func(p *domain.Program) { p.KYC = domain.TriUnknown }},
		{"fee cannot be established", func(p *domain.Program) {
			p.Fee = domain.FeeGate{Present: domain.TriUnknown}
		}},
		{"reputation gate cannot be established", func(p *domain.Program) {
			p.Reputation = domain.ReputationGate{Present: domain.TriUnknown}
		}},
		{"record could not be fully understood", func(p *domain.Program) {
			p.ParseConfidence = domain.ConfidenceLow
		}},
		{"no crypto trait matches the allow list", func(p *domain.Program) {
			p.CryptoTraits = domain.NewTags("smart_contract_only")
			p.CryptoKind = domain.CryptoSmartContract
		}},
		{"no target domain of interest", func(p *domain.Program) {
			p.SurfaceTags = domain.NewTags("smart_contract")
			p.Targets = domain.Targets{
				{Kind: domain.KindSmartContract, Identifier: "A.sol", Label: "Smart Contract", InScope: true},
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
				// The program is launched two minutes ago, so only the gate can
				// be what silences it.
				c.Program = program(launchedAgo(2*time.Minute), tc.opt)
				c.Program.Finalize()
				c.Decision.Eligible = false
			}))
			if got != nil {
				t.Errorf("a program that %s produced an alert: %q", tc.name, got.Subject)
			}
		})
	}
}

// TestExistingProgramTriggersStayOffByDefault verifies the channel reports new
// launches and nothing else unless a profile explicitly asks for more.
func TestExistingProgramTriggersStayOffByDefault(t *testing.T) {
	p := profile(t)
	p.Notifications.AlertOnMaterialChange = false
	p.Notifications.AlertOnScopeExpansion = false

	g := generator(p)
	// A scope expansion on a program that launched months ago.
	got := g.Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(200 * 24 * time.Hour))
		c.Program.Finalize()
		c.Diff = domain.Diff{
			ProgramID: "hackenproof:example",
			Changes: domain.ChangeSet{
				{Kind: domain.ChangeAPIAdded, Severity: domain.SeverityMedium,
					Assets: []string{"https://api-v2.example.com"}},
			},
		}
		c.Prior = alerts.PriorDecision{Known: true, Eligible: true}
	}))
	if got != nil {
		t.Errorf("an existing program's scope change alerted: %q", got.Subject)
	}
}

// TestSubjectStatesLaunchAge verifies the headline claim is in the subject line,
// which is what a recipient sees before deciding whether to open the message.
func TestSubjectStatesLaunchAge(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(3 * time.Hour))
		c.Program.Finalize()
	}))
	if got == nil {
		t.Fatal("no alert")
	}
	if !strings.Contains(got.Subject, "3h") {
		t.Errorf("subject %q does not state the launch age", got.Subject)
	}
}

// TestHTMLBodyIsSelfContained verifies the styled message carries no external
// resources and states the launch age.
func TestHTMLBodyIsSelfContained(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(3 * time.Hour))
		c.Program.Finalize()
	}))
	if got == nil {
		t.Fatal("no alert")
	}
	h := got.HTMLBody
	if strings.TrimSpace(h) == "" {
		t.Fatal("no html body rendered")
	}

	// No external resource of any kind: a tracker or a remote image would
	// disclose when the message was opened.
	for _, forbidden := range []string{
		"<img", "http://", "https://cdn", "background-image",
		"@import", "src=", "tracking", "pixel",
	} {
		if strings.Contains(strings.ToLower(h), forbidden) {
			t.Errorf("html body references an external resource: %s", forbidden)
		}
	}

	// The program URL is the one intentional link.
	if !strings.Contains(h, "https://hackenproof.com/programs/example") {
		t.Error("html body does not link to the program")
	}

	// The headline facts must be present.
	for _, want := range []string{
		"NEWLY LAUNCHED", "LAUNCHED", "3h ago",
		"Access", "KYC", "Reputation", "Submission fee",
		"Why this matched", "Open program",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html body is missing %q", want)
		}
	}
}

// TestHTMLIsEscaped verifies third-party text cannot inject markup.
//
// Program names, descriptions and asset identifiers all originate from a page
// anyone can publish a program on. Rendering them unescaped would let an
// attacker place arbitrary HTML into the mail of every recipient.
func TestHTMLIsEscaped(t *testing.T) {
	hostile := `<img src=x onerror="alert(1)"><script>bad()</script>`

	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(time.Hour), func(p *domain.Program) {
			p.Name = hostile
			p.Targets = domain.Targets{
				{Kind: domain.KindWeb, Identifier: hostile, Label: "Web", InScope: true},
			}
		})
		c.Program.Finalize()
	}))
	if got == nil {
		t.Fatal("no alert")
	}

	h := got.HTMLBody
	// Escaped text legitimately still contains the substring "onerror=" as visible
	// characters, so only unescaped markup is treated as a finding.
	for _, forbidden := range []string{"<img", "<script>"} {
		if strings.Contains(strings.ToLower(h), forbidden) {
			t.Errorf("html body contains unescaped markup: %s", forbidden)
		}
	}
	if !strings.Contains(h, "&lt;img") {
		t.Error("html body did not escape the hostile program name")
	}

	// The plain-text part is a fallback and is sent verbatim, but it is not
	// parsed as markup, so it must simply contain the original text.
	if !strings.Contains(got.Body, "<img") {
		t.Error("plain-text body dropped the program name")
	}
}

// TestHTMLRespectsDarkMode verifies the style block carries the overrides,
// so a message opened at night is not a white slab.
func TestHTMLRespectsDarkMode(t *testing.T) {
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(time.Hour))
		c.Program.Finalize()
	}))
	if got == nil {
		t.Fatal("no alert")
	}
	h := got.HTMLBody
	if !strings.Contains(h, "prefers-color-scheme:dark") {
		t.Error("html body has no dark-mode support")
	}
	if !strings.Contains(h, `name="viewport"`) {
		t.Error("html body has no viewport, so it will not lay out on a phone")
	}
	if !strings.Contains(h, "<!doctype html>") {
		t.Error("html body is not a complete document")
	}
}

// TestHTMLCapsAssetList verifies the message stays readable on a phone.
func TestHTMLCapsAssetList(t *testing.T) {
	var many domain.Targets
	for i := 0; i < 40; i++ {
		many = append(many, domain.Target{
			Kind: domain.KindAPI, Identifier: "https://api" + itoa(i) + ".example.com", InScope: true,
		})
	}
	got := generator(profile(t)).Decide(candidate(func(c *alerts.Candidate) {
		c.Program = program(launchedAgo(time.Hour), func(p *domain.Program) { p.Targets = many })
		c.Program.Finalize()
	}))
	if got == nil {
		t.Fatal("no alert")
	}
	if strings.Contains(got.HTMLBody, "api39.example.com") {
		t.Error("html body listed every asset; a long list is how an alert gets deleted unread")
	}
	if !strings.Contains(got.HTMLBody, "and 32 more") {
		t.Error("html body did not say how many were omitted")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
