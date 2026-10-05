package alerts

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// RenderHTML produces the styled alternative to the plain-text body.
//
// Design constraints, in priority order:
//
//  1. The event that triggered the alert is the largest thing on the page. A
//     change alert must not be presented as a launch alert; each trigger has its
//     own evidence and its own headline.
//  2. Access gates are shown as confirmed, because an alert only exists once
//     they have all passed. Showing them as checkmarks is a reassurance the
//     recipient has earned, not a claim they have to verify.
//  3. No external resources of any kind. No images, no web fonts, no tracking
//     pixel. Every rule is inline or in a style block, so the message renders
//     identically offline and leaks nothing about when it was opened.
//  4. Light and dark are both first-class, because an alert is read at night as
//     often as in daylight.
//
// The output is deterministic for a given candidate.
func RenderHTML(c Candidate, profile *config.Profile, now time.Time) string {
	c.LaunchAge, c.LaunchKnown = launchAge(c.Program, now)
	trigger := selectedTrigger(c, profile, now)
	return renderHTML(c, profile, now, trigger)
}

func renderHTML(c Candidate, profile *config.Profile, now time.Time, trigger domain.AlertKind) string {
	var b strings.Builder
	p := c.Program

	b.WriteString(htmlHeader())
	b.WriteString(htmlWrap(c, func() string {
		return htmlHero(c, trigger, profile, now) +
			htmlGates(p) +
			htmlSurface(p) +
			htmlCrypto(p) +
			htmlWhy(c) +
			htmlCompetition(p) +
			htmlCTA(p) +
			htmlFooter(trigger, profile)
	}))
	return b.String()
}

// htmlWrap builds the outer layout.
//
// A table is used for the outer container because Outlook's renderer ignores
// modern layout entirely; the table is the only structure that survives it.
func htmlWrap(c Candidate, content func() string) string {
	return strings.NewReplacer("\n", "").Replace(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef1f6;padding:0;"><tr><td align="center" style="padding:24px 12px;"><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" class="card" style="width:100%;max-width:600px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 2px 16px rgba(16,24,40,.08);">` +
		`<tr><td style="padding:28px 28px 8px 28px;">` + content() + `</td></tr>` +
		`</table>` +
		`<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;"><tr><td align="center" style="padding:14px 0 0 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:11px;line-height:18px;color:#98a2b3;">` +
		fmt.Sprintf("%s &middot; scan %s &middot; automated opportunity monitor", escapeHTML(c.Program.Source), escapeHTML("")) +
		`</td></tr></table>` +
		`</td></tr></table>`)
}

// htmlHero is the headline block for the trigger that produced the alert.
func htmlHero(c Candidate, trigger domain.AlertKind, profile *config.Profile, now time.Time) string {
	var b strings.Builder

	p := c.Program
	launchLabel, launchKnown := launchHeadline(c)
	badgeLabel, badgeAccent := triggerHeadline(trigger)
	b.WriteString(badge(badgeLabel, badgeAccent))
	b.WriteString(`<div style="height:14px"></div>`)
	b.WriteString(fmt.Sprintf(
		`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:24px;line-height:30px;font-weight:700;color:%s;letter-spacing:-.4px;">%s</div>`,
		palette.Ink, escapeHTML(p.Name)))

	b.WriteString(`<div style="height:16px"></div>`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>`)
	if trigger == domain.AlertNewQualifying || trigger == domain.AlertNewlyEligible {
		b.WriteString(htmlStat("LAUNCHED", launchLabel, accentIf(launchKnown, palette.Green, palette.Amber)))
		b.WriteString(htmlStat("YOU NOTICED IT", domain.HumanizeDuration(c.Fresh.FirstSeenAge), palette.Blue))
	} else {
		observed := triggerObservation(c, trigger, profile, now)
		ageLabel := "unknown"
		if observed.Known() {
			ageLabel = observed.Humanize(now)
		}
		b.WriteString(htmlStat("CHANGE OBSERVED", ageLabel, palette.Blue))
		b.WriteString(htmlStat("PROGRAM AGE", launchLabel, accentIf(launchKnown, palette.Muted, palette.Amber)))
	}
	b.WriteString(`</tr></table>`)

	if p.MaxBountyUSD != nil {
		b.WriteString(htmlStatLine("Bounty ceiling", fmt.Sprintf("$%.0f", *p.MaxBountyUSD)))
	}
	return b.String()
}

func triggerHeadline(trigger domain.AlertKind) (string, string) {
	switch trigger {
	case domain.AlertNewQualifying:
		return "NEWLY LAUNCHED", palette.Green
	case domain.AlertNewlyEligible:
		return "NEWLY ELIGIBLE", palette.Green
	case domain.AlertScopeExpansion:
		return "SCOPE EXPANDED", palette.Blue
	case domain.AlertMaterialChange:
		return "PROGRAM CHANGED", palette.Amber
	default:
		return "PROGRAM UPDATE", palette.Amber
	}
}

// triggerObservation returns the bounded evidence associated with the selected
// trigger. The span is shown as a range because the scan observes a transition
// between reads, not at a point in time.
func triggerObservation(c Candidate, trigger domain.AlertKind, profile *config.Profile, now time.Time) domain.ObservationInterval {
	var observed domain.ObservationInterval
	for _, change := range c.Diff.Changes {
		if !change.Alertable() {
			continue
		}
		if trigger == domain.AlertScopeExpansion && !isSurfaceExpansion(change) {
			continue
		}
		interval, ok := changeInterval(c.Fresh, change.Kind)
		if !ok || !interval.PossiblyWithin(now, profile.ChangeWindowFor(change.Kind)) {
			continue
		}
		if !observed.Known() {
			observed = interval
			continue
		}
		if interval.NotBefore.Before(observed.NotBefore) {
			observed.NotBefore = interval.NotBefore
		}
		if interval.NotAfter.After(observed.NotAfter) {
			observed.NotAfter = interval.NotAfter
		}
	}
	return observed
}

// htmlGates renders the access requirements as confirmed facts.
//
// Reaching this point means every gate below already passed: the policy engine
// blocks ineligible programs before an alert is generated, so these are
// statements the recipient can rely on rather than things to check.
func htmlGates(p domain.Program) string {
	var b strings.Builder
	b.WriteString(sectionTitle("Access &mdash; all requirements met"))

	items := []struct{ label, value string }{
		{"Reputation", reputationValue(p.Reputation)},
		{"KYC", triValue(p.KYC, "Not required", "Required")},
		{"Submission fee", feeValue(p.Fee)},
		{"Proof of concept", triValue(p.POC, "Not required", "Required")},
	}

	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`)
	for _, it := range items {
		b.WriteString(fmt.Sprintf(
			`<tr><td style="padding:7px 0;border-bottom:1px solid %s;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;color:%s;">%s</td>`+
				`<td align="right" style="padding:7px 0;border-bottom:1px solid %s;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;font-weight:600;color:%s;">%s</td></tr>`,
			palette.Hairline, palette.Muted, escapeHTML(it.label),
			palette.Hairline, palette.Ink, escapeHTML(it.value)))
	}
	b.WriteString(`</table>`)
	return b.String()
}

// htmlSurface renders what is actually in scope.
func htmlSurface(p domain.Program) string {
	targets := p.InScopeTargets()
	if len(targets) == 0 && len(p.SurfaceTags) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(sectionTitle("Attack surface"))

	if len(p.SurfaceTags) > 0 {
		b.WriteString(chips(p.SurfaceTags, palette.Blue, palette.BlueBg))
	}
	if len(p.CapabilityTags) > 0 {
		b.WriteString(`<div style="height:8px"></div>`)
		b.WriteString(fmt.Sprintf(
			`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:18px;color:%s;">%s</div>`,
			palette.Muted, "Focus areas: "+escapeHTML(p.CapabilityTags.Join())))
	}

	// Assets are capped. An alert is read on a phone; a hundred hostnames is
	// how a message gets deleted rather than read.
	if len(targets) > 0 {
		shown := targets
		extra := 0
		if len(shown) > 8 {
			extra = len(shown) - 8
			shown = shown[:8]
		}
		b.WriteString(`<div style="height:12px"></div>`)
		b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`)
		for _, t := range shown {
			id := t.Identifier
			if id == "" {
				id = t.Label
			}
			b.WriteString(fmt.Sprintf(
				`<tr><td style="padding:4px 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:18px;color:%s;word-break:break-all;">&middot; %s</td></tr>`,
				palette.Ink, escapeHTML(id)))
		}
		if extra > 0 {
			b.WriteString(fmt.Sprintf(
				`<tr><td style="padding:4px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:18px;color:%s;">&middot; and %d more</td></tr>`,
				palette.Muted, extra))
		}
		b.WriteString(`</table>`)
	}
	return b.String()
}

// htmlCrypto renders the crypto verdict, which is what separates a crypto
// business with a web surface from protocol research.
func htmlCrypto(p domain.Program) string {
	if p.CryptoKind == "" || p.CryptoKind == domain.CryptoNotCrypto {
		return ""
	}

	label, accent := cryptoVerdict(p.CryptoKind)
	var b strings.Builder
	b.WriteString(sectionTitle("Classification"))
	b.WriteString(badge(label, accent))
	if len(p.CryptoTraits) > 0 {
		b.WriteString(fmt.Sprintf(
			`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:18px;color:%s;">%s</div>`,
			palette.Muted, escapeHTML(p.CryptoTraits.Join())))
	}
	return b.String()
}

// htmlWhy renders the eligibility reasoning, which is what makes a rejection
// defensible and a match trustworthy.
func htmlWhy(c Candidate) string {
	if len(c.Decision.Reasons) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(sectionTitle("Why this matched"))
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`)
	for _, r := range c.Decision.Reasons {
		if isIntegrityReason(r) {
			continue
		}
		b.WriteString(fmt.Sprintf(
			`<tr><td valign="top" style="padding:3px 8px 3px 0;font-size:15px;line-height:20px;color:%s;">&#10003;</td>`+
				`<td style="padding:3px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:20px;color:%s;">%s</td></tr>`,
			palette.Green, palette.Muted, escapeHTML(r)))
	}
	b.WriteString(`</table>`)
	return b.String()
}

// htmlCompetition renders the raw submission count.
//
// The number is printed without editorialising: a submission count is a weak
// proxy for competition and any framing would overstate what is known.
func htmlCompetition(p domain.Program) string {
	if !p.SubmittedReportsKnown || p.SubmittedReports == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(sectionTitle("Competition"))
	b.WriteString(htmlStatLine("Submissions reported", fmt.Sprintf("%d", *p.SubmittedReports)))
	if p.RewardsPaidUSD != nil {
		b.WriteString(htmlStatLine("Paid out to date", fmt.Sprintf("$%.0f", *p.RewardsPaidUSD)))
	}
	return b.String()
}

// htmlCTA is the call to action.
func htmlCTA(p domain.Program) string {
	if p.URL == "" {
		return ""
	}
	return fmt.Sprintf(
		`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="margin-top:26px;"><tr><td align="center" bgcolor="%s" style="border-radius:10px;">`+
			`<a href="%s" style="display:inline-block;padding:15px 30px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;letter-spacing:.1px;">Open program &rarr;</a>`+
			`</td></tr></table>`+
			`<div style="height:10px"></div>`+
			`<div align="center" style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;line-height:17px;color:%s;word-break:break-all;">%s</div>`,
		palette.Accent, escapeHTML(p.URL), palette.Muted, escapeHTML(p.URL))
}

// htmlFooter states why this specific trigger was sent and what the scores mean.
func htmlFooter(trigger domain.AlertKind, profile *config.Profile) string {
	reason := "a configured opportunity trigger matched"
	switch trigger {
	case domain.AlertNewQualifying:
		reason = "the program launched within " + humanDuration(profile.NewProgramWindow())
	case domain.AlertNewlyEligible:
		reason = "the program became eligible within its configured launch window"
	case domain.AlertScopeExpansion:
		reason = "an attack-surface expansion was observed within its configured change window"
	case domain.AlertMaterialChange:
		reason = "a material change was observed within its configured change window"
	}
	return `<div style="height:26px"></div>` +
		`<div style="border-top:1px solid ` + palette.Hairline + `;padding-top:14px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:11px;line-height:17px;color:` + palette.Muted + `;">` +
		`Sent because ` + escapeHTML(reason) + ` and the program passed every access gate in the ` + escapeHTML(profile.Name) + ` profile.<br>` +
		`Scores order your reading; they do not estimate how likely a bug is to be found.` +
		`</div>`
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

// palette holds every colour used, so that dark mode is a single override in
// the style block rather than a second set of templates.
type paletteT struct {
	Accent   string
	Ink      string
	Muted    string
	Hairline string
	Green    string
	GreenBg  string
	Amber    string
	AmberBg  string
	Blue     string
	BlueBg   string
	PageBg   string
	CardBg   string
}

var palette = paletteT{
	Accent:   "#3b5bfd",
	Ink:      "#101828",
	Muted:    "#667085",
	Hairline: "#eaecf0",
	Green:    "#067647",
	GreenBg:  "#ecfdf3",
	Amber:    "#b54708",
	AmberBg:  "#fffaeb",
	Blue:     "#175cd3",
	BlueBg:   "#eff8ff",
	PageBg:   "#eef1f6",
	CardBg:   "#ffffff",
}

// htmlHeader returns the document head.
//
// The style block carries only the dark-mode overrides and the mobile width.
// Everything structural is inline, because inline styles are the only thing
// every mail client agrees on.
func htmlHeader() string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<meta name="color-scheme" content="light dark">` +
		`<meta name="supported-color-schemes" content="light dark">` +
		`<title>Hunter opportunity alert</title>` +
		`<style>` +
		`@media (prefers-color-scheme:dark){` +
		`body,.wrap{background:#0b0f19 !important;}` +
		`.card{background:#121826 !important;box-shadow:none !important;}` +
		`.ink{color:#e6eaf2 !important;}` +
		`.muted{color:#98a2b3 !important;}` +
		`.hair{border-color:#1f2937 !important;}` +
		`}` +
		`@media (max-width:600px){.pad{padding-left:18px !important;padding-right:18px !important;}}` +
		`</style></head><body class="wrap" style="margin:0;padding:0;background:` + palette.PageBg + `;">`
}

// badge renders a small pill label.
func badge(text, accent string) string {
	return fmt.Sprintf(
		`<span style="display:inline-block;padding:5px 10px;border-radius:999px;background:%s;color:%s;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:.6px;">%s</span>`,
		lightBgFor(accent), accent, text)
}

// lightBgFor returns the soft background matching an accent colour.
func lightBgFor(accent string) string {
	switch accent {
	case palette.Green:
		return palette.GreenBg
	case palette.Amber:
		return palette.AmberBg
	default:
		return palette.BlueBg
	}
}

// accentIf chooses a colour based on a condition, for marking verified claims
// differently from unverified ones.
func accentIf(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// htmlStat renders one of the two headline figures.
func htmlStat(label, value, accent string) string {
	return fmt.Sprintf(
		`<td width="50%%" valign="top" style="padding:12px 14px;background:%s;border-radius:12px;">`+
			`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:10px;font-weight:700;letter-spacing:.7px;color:%s;text-transform:uppercase;">%s</div>`+
			`<div style="padding-top:3px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:21px;font-weight:700;color:%s;letter-spacing:-.3px;">%s</div></td>`,
		palette.CardBg, palette.Muted, escapeHTML(label), accent, escapeHTML(value))
}

// htmlStatLine renders a label and value pair in the plain rows used below the
// headline.
func htmlStatLine(label, value string) string {
	return fmt.Sprintf(
		`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0"><tr>`+
			`<td style="padding:6px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:19px;color:%s;">%s</td>`+
			`<td align="right" style="padding:6px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:19px;font-weight:600;color:%s;">%s</td></tr></table>`,
		palette.Muted, escapeHTML(label), palette.Ink, escapeHTML(value))
}

// sectionTitle renders a section heading.
func sectionTitle(title string) string {
	return fmt.Sprintf(
		`<div style="padding:22px 0 8px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:%s;">%s</div>`,
		palette.Muted, title)
}

// chips renders a tag set as inline pills.
func chips(tags domain.Tags, accent, bg string) string {
	parts := make([]string, 0, len(tags))
	for _, t := range tags {
		parts = append(parts, fmt.Sprintf(
			`<span style="display:inline-block;margin:0 6px 6px 0;padding:5px 10px;border-radius:8px;background:%s;color:%s;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:12px;font-weight:600;">%s</span>`,
			bg, accent, escapeHTML(t)))
	}
	return `<div style="font-size:0;line-height:0;">` + strings.Join(parts, "") + `</div>`
}

// cryptoVerdict maps a crypto classification onto a label and colour.
func cryptoVerdict(k domain.CryptoKind) (label, accent string) {
	switch k {
	case domain.CryptoPlatform:
		return "CRYPTO PLATFORM", palette.Green
	case domain.CryptoMixed:
		return "CRYPTO &mdash; PLATFORM AND PROTOCOL", palette.Amber
	case domain.CryptoSmartContract:
		return "SMART CONTRACT ONLY", palette.Muted
	case domain.CryptoProtocol:
		return "PROTOCOL RESEARCH", palette.Muted
	default:
		return "CRYPTO &mdash; UNCLASSIFIED", palette.Amber
	}
}

// launchHeadline produces the single most important phrase in the message.
func launchHeadline(c Candidate) (string, bool) {
	if !c.LaunchKnown {
		return "not published", false
	}
	return HumanizeAge(c.LaunchAge) + " ago", true
}

// reputationValue renders the reputation gate.
func reputationValue(g domain.ReputationGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("%d points", g.Points)
	case domain.TriNo:
		return "None required"
	default:
		return "Unknown"
	}
}

// feeValue renders the submission fee.
func feeValue(g domain.FeeGate) string {
	switch g.Present {
	case domain.TriYes:
		return fmt.Sprintf("$%.2f", g.USD)
	case domain.TriNo:
		return "None"
	default:
		return "Unknown"
	}
}

// triValue renders a tri-state.
func triValue(t domain.Tri, noLabel, yesLabel string) string {
	switch t {
	case domain.TriYes:
		return yesLabel
	case domain.TriNo:
		return noLabel
	default:
		return "Unknown"
	}
}

// integrityPhrases identify reasons that describe record quality rather than
// the opportunity.
var integrityPhrases = []string{
	"fully understood", "partially understood", "access facts present",
}

// isIntegrityReason reports whether a reason describes record quality.
func isIntegrityReason(r string) bool {
	for _, p := range integrityPhrases {
		if strings.Contains(r, p) {
			return true
		}
	}
	return false
}

// humanDuration renders a duration for the footer.
func humanDuration(d interface{ String() string }) string {
	return d.String()
}

// escapeHTML escapes text for safe inclusion in the message.
//
// Program names, descriptions and asset identifiers all originate from a
// third-party page. Rendering them unescaped would allow an attacker who can
// publish a program to inject markup into the mail of everyone who receives an
// alert about it.
func escapeHTML(s string) string { return html.EscapeString(s) }

// sortedKeys is retained for deterministic iteration over maps in future
// sections; declared here so the helper stays with the renderer.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
