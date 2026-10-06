package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/config"
	"github.com/eadeshina/hunter/internal/domain"
)

// Render produces the subject and both bodies for one candidate.
//
// The body is deliberately built for a phone: short lines, the decision facts
// first, then what changed, then why. Prose from the source is never included,
// because program descriptions routinely run to thousands of characters and
// would bury the signal in a notification. The trigger determines which clock is
// prominent: launch alerts use the launch age, while change alerts use their
// bounded observation interval and keep program age separate.
//
// The clock is supplied rather than read from the environment, so all rendered
// ages use one reference instant and output is deterministic for a candidate.
func Render(c Candidate, profile *config.Profile, now time.Time) (subject, body, htmlBody string) {
	c.LaunchAge, c.LaunchKnown = launchAge(c.Program, now)
	trigger := selectedTrigger(c, profile, now)

	subject = renderSubject(c, profile, now, trigger)
	return subject, renderBody(c, profile, now, trigger), renderHTML(c, profile, now, trigger)
}

// renderSubject builds the one-line summary.
//
// The format is fixed: prefix, kind, name, surface, and the age evidence for the
// selected trigger. Launch alerts use the launch age; change alerts use the
// bounded change interval. This is often the only timing evidence read before a
// recipient decides whether to open the message.
func renderSubject(c Candidate, profile *config.Profile, now time.Time, trigger domain.AlertKind) string {
	prefix := strings.TrimSpace(profile.Notifications.SubjectPrefix)
	kind := subjectKind(c, trigger)
	surface := headlineSurface(c.Program)
	age := triggerAge(c, profile, now, trigger)

	parts := nonEmpty([]string{prefix, kind, displayName(c.Program), surface, age})
	// The prefix commonly ends in a bracket, so appending the separator would
	// render as "[HUNTER] — — NEW MATCH". One separator per join is enough.
	return strings.Join(parts, " — ")
}

// subjectKind is the short kind label used in the subject line.
func subjectKind(c Candidate, trigger domain.AlertKind) string {
	switch trigger {
	case domain.AlertNewQualifying:
		return "NEW MATCH"
	case domain.AlertNewlyEligible:
		return "NOW ELIGIBLE"
	case domain.AlertScopeExpansion:
		return "SCOPE EXPANDED"
	case domain.AlertMaterialChange:
		if c.Diff.Changes.Contains(domain.ChangeProgramReactivated) {
			return "REACTIVATED"
		}
		return "CHANGED"
	default:
		if c.Diff.IsNew {
			return "NEW MATCH"
		}
		if c.Prior.Known && !c.Prior.Eligible && c.Decision.Eligible {
			return "NOW ELIGIBLE"
		}
		if c.Diff.Changes.Contains(domain.ChangeProgramReactivated) {
			return "REACTIVATED"
		}
		if hasSurfaceExpansion(c) {
			return "SCOPE EXPANDED"
		}
		return "CHANGED"
	}
}

// renderBody builds the message body.
func renderBody(c Candidate, profile *config.Profile, now time.Time, trigger domain.AlertKind) string {
	var b strings.Builder

	headline := "MATERIAL CHANGE"
	switch trigger {
	case domain.AlertNewQualifying:
		headline = "NEW QUALIFYING OPPORTUNITY"
	case domain.AlertNewlyEligible:
		headline = "PREVIOUSLY EXCLUDED — NOW QUALIFYING"
	case domain.AlertScopeExpansion:
		headline = "ATTACK SURFACE EXPANDED"
	case domain.AlertMaterialChange:
		if c.Diff.Changes.Contains(domain.ChangeProgramReactivated) {
			headline = "PROGRAM REACTIVATED"
		}
	default:
		if c.Diff.IsNew {
			headline = "NEW QUALIFYING OPPORTUNITY"
		} else if c.Prior.Known && !c.Prior.Eligible && c.Decision.Eligible {
			headline = "PREVIOUSLY EXCLUDED — NOW QUALIFYING"
		} else if c.Diff.Changes.Contains(domain.ChangeProgramReactivated) {
			headline = "PROGRAM REACTIVATED"
		} else if hasSurfaceExpansion(c) {
			headline = "ATTACK SURFACE EXPANDED"
		}
	}
	b.WriteString(headline)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("=", len(headline)))
	b.WriteString("\n\n")

	writeField(&b, "Program", c.Program.Name)
	if trigger == domain.AlertScopeExpansion || trigger == domain.AlertMaterialChange {
		observed := triggerObservation(c, trigger, profile, now)
		age := "unknown"
		if observed.Known() {
			age = observed.Humanize(now)
		}
		writeField(&b, "Change observed", age)
	} else if age := headlineAge(c); age != "" {
		writeField(&b, "Detected", age)
	}
	if c.LaunchKnown {
		writeField(&b, "Started", domain.HumanizeDuration(c.LaunchAge))
	}
	if c.Program.State != domain.StateUnknown {
		writeField(&b, "State", string(c.Program.State))
	}

	writeAccess(&b, c.Program)
	writeSurface(&b, c.Program)
	writeCrypto(&b, c.Program, profile)
	writeCompetition(&b, c.Program)
	writeChanges(&b, c)
	writeReasons(&b, c.Decision)
	writeTriage(&b, c.Triage)
	writeFreshness(&b, c.Fresh, now)

	if c.Program.URL != "" {
		b.WriteString("\nOpen:\n")
		b.WriteString(c.Program.URL)
		b.WriteString("\n")
	}
	return b.String()
}

// writeAccess renders the entry gates, which are what determine whether the
// program is reachable at all.
//
// Every line is marked, and an unknown fact is marked differently from a
// satisfied one. That distinction is the whole point: a reader must be able to
// see at a glance that a gate could not be determined rather than assume it is
// clear.
func writeAccess(b *strings.Builder, p domain.Program) {
	b.WriteString("\nAccess:\n")
	writeGate(b, "Reputation", markReputation(p.Reputation))
	writeGate(b, "KYC", triMark(p.KYC, "not required", "required"))
	writeGate(b, "Submission fee", markFee(p.Fee))
	writeGate(b, "Proof of concept", triMark(p.POC, "not required", "required"))

	// The bounty is a fact about the program, not a gate the researcher must
	// pass. Keeping it outside the marked list is what lets the marker mean
	// "this gate is known and acceptable" and nothing else.
	if p.MaxBountyUSD != nil {
		b.WriteString("  Bounty ceiling: " + usd(*p.MaxBountyUSD) + "\n")
	}
}

// markReputation renders the reputation gate with an explicit unknown marker.
func markReputation(g domain.ReputationGate) string {
	switch g.Present {
	case domain.TriYes:
		return "✓ " + itoa(g.Points) + " points required"
	case domain.TriNo:
		return "✓ none required"
	default:
		return "? UNKNOWN - the source did not state a requirement that could be read"
	}
}

// markFee renders the submission fee with an explicit unknown marker.
func markFee(g domain.FeeGate) string {
	switch g.Present {
	case domain.TriYes:
		return "✓ " + usd(g.USD)
	case domain.TriNo:
		return "✓ none"
	default:
		return "? UNKNOWN - the platform states fees in the account currency"
	}
}

func usd(v float64) string { return fmt.Sprintf("$%.2f", v) }

// triMark renders a tri-state as a marked line.
//
// An unknown fact is marked with a question mark rather than a checkmark,
// because a checkmark would assert something the system does not know.
func triMark(t domain.Tri, noLabel, yesLabel string) string {
	switch t {
	case domain.TriYes:
		return "✓ " + yesLabel
	case domain.TriNo:
		return "✓ " + noLabel
	default:
		return "? UNKNOWN"
	}
}

func writeGate(b *strings.Builder, label, value string) {
	b.WriteString("  " + label + ": " + value + "\n")
}

// writeSurface renders the detected attack surface.
func writeSurface(b *strings.Builder, p domain.Program) {
	b.WriteString("\nAttack surface:\n")
	if len(p.SurfaceTags) == 0 {
		b.WriteString("  ? none detected\n")
	} else {
		for _, t := range p.SurfaceTags {
			b.WriteString("  ✓ " + t + "\n")
		}
	}
	if len(p.CapabilityTags) > 0 {
		b.WriteString("  Capabilities: " + p.CapabilityTags.Join() + "\n")
	}
	if targets := p.InScopeTargets(); len(targets) > 0 {
		b.WriteString("  Assets (" + itoa(len(targets)) + "):\n")
		for _, t := range targets {
			marker := "✓"
			if !t.InScope {
				marker = "✗"
			}
			id := t.Identifier
			if id == "" {
				id = t.Label
			}
			b.WriteString("    " + marker + " " + id + "\n")
		}
	}
}

// writeCrypto renders the crypto verdict, which is the distinction that
// separates a crypto business from protocol research.
func writeCrypto(b *strings.Builder, p domain.Program, profile *config.Profile) {
	if p.CryptoKind == "" || p.CryptoKind == domain.CryptoNotCrypto {
		return
	}
	b.WriteString("\nCrypto classification:\n")
	switch p.CryptoKind {
	case domain.CryptoPlatform:
		b.WriteString("  ✓ crypto platform\n")
	case domain.CryptoMixed:
		b.WriteString("  ~ mixed platform and protocol\n")
	case domain.CryptoSmartContract:
		b.WriteString("  ✗ smart-contract-only\n")
	case domain.CryptoProtocol:
		b.WriteString("  ✗ protocol research\n")
	default:
		b.WriteString("  ? " + string(p.CryptoKind) + "\n")
	}
	if len(p.CryptoTraits) > 0 {
		b.WriteString("  Traits: " + p.CryptoTraits.Join() + "\n")
	}
}

// writeCompetition renders the raw submission count.
//
// The number is printed without interpretation, because a submission count is a
// weak proxy for competition and any editorial framing would overstate what the
// platform actually published.
func writeCompetition(b *strings.Builder, p domain.Program) {
	if !p.SubmittedReportsKnown || p.SubmittedReports == nil {
		return
	}
	b.WriteString("\nCompetition (reported by platform):\n")
	b.WriteString("  " + itoa(*p.SubmittedReports) + " submissions\n")
	if p.RewardsPaidUSD != nil {
		b.WriteString("  $" + fmt.Sprintf("%.0f", *p.RewardsPaidUSD) + " paid out to date\n")
	}
}

// writeChanges renders what is new, additions first because they are what the
// researcher should act on.
func writeChanges(b *strings.Builder, c Candidate) {
	if c.Diff.IsNew {
		b.WriteString("\nIn scope:\n")
		listed := writeAssetAdditions(b, c.Program)
		if !listed {
			b.WriteString("  (no in-scope assets were published)\n")
		}
		return
	}
	if len(c.Diff.Changes) == 0 {
		return
	}
	b.WriteString("\nChanges detected:\n")
	for _, ch := range c.Diff.Changes {
		if line := changeLine(ch); line != "" {
			b.WriteString("  " + line + "\n")
		}
	}
}

// changeLine renders one change with an addition-first marker.
func changeLine(c domain.Change) string {
	mark := "~"
	switch c.Kind {
	case domain.ChangeTargetAdded, domain.ChangeAPIAdded,
		domain.ChangeRepositoryAdded, domain.ChangeMobileAdded:
		mark = "+"
	case domain.ChangeTargetRemoved, domain.ChangeAPIRemoved,
		domain.ChangeRepositoryRemoved:
		mark = "-"
	}

	var body string
	switch {
	case len(c.Assets) > 0:
		shown := c.Assets
		if len(shown) > 5 {
			shown = append(append([]string{}, shown[:5]...), fmt.Sprintf("(+%d more)", len(c.Assets)-5))
		}
		body = strings.Join(shown, ", ")
	case c.Before != "" && c.After != "":
		body = c.Before + " → " + c.After
	case c.After != "":
		body = c.After
	case c.Detail != "":
		body = c.Detail
	default:
		body = string(c.Kind)
	}
	return mark + " " + strings.ToLower(strings.ReplaceAll(string(c.Kind), "_", " ")) + ": " + body
}

// writeAssetAdditions lists the in-scope assets of a newly seen program and
// reports whether anything was listed.
func writeAssetAdditions(b *strings.Builder, p domain.Program) bool {
	wrote := false
	for _, t := range p.InScopeTargets() {
		id := t.Identifier
		if id == "" {
			id = t.Label
		}
		if id == "" {
			continue
		}
		b.WriteString("  + " + id + "\n")
		wrote = true
	}
	return wrote
}

// writeReasons renders the eligibility explanation. This is the section that
// makes the message defensible: every line corresponds to a policy check.
func writeReasons(b *strings.Builder, d domain.EligibilityDecision) {
	if len(d.Reasons) == 0 {
		return
	}
	b.WriteString("\nWhy this matched:\n")
	for _, r := range d.Reasons {
		b.WriteString("  - " + r + "\n")
	}
	if !d.Eligible && len(d.Blockers) > 0 {
		b.WriteString("\nBlocking checks:\n")
		for _, c := range d.Blockers {
			b.WriteString("  ! " + c.Reason() + "\n")
		}
	}
}

// writeTriage renders the exposed score components.
//
// Every component is printed with its own value. The total is shown too, but it
// is explicitly labelled as an attention-priority aid rather than a likelihood
// estimate.
func writeTriage(b *strings.Builder, t domain.Triage) {
	if len(t.Components) == 0 {
		return
	}
	b.WriteString("\nAttention priority (ordering aid, not a success estimate): ")
	b.WriteString(itoa(t.Total))
	b.WriteString("/100\n")
	for _, c := range t.Components {
		b.WriteString("  " + padRight(c.Name, 20) + itoa(c.Value) + "  " + c.Basis + "\n")
	}
}

// writeFreshness renders the independent age signals, omitting any that are
// unavailable rather than printing zero.
//
// Change signals render as bounded ranges because that is the width of the
// evidence. "scope changed: within the last 9m-14m" tells the reader both that
// the change is recent and that the exact moment is not known, which is the
// claim the system can actually support.
func writeFreshness(b *strings.Builder, f domain.Freshness, now time.Time) {
	lines := f.AgeStringsAt(now)
	if len(lines) == 0 {
		return
	}
	b.WriteString("\nTiming:\n")
	for _, l := range lines {
		b.WriteString("  - " + l + "\n")
	}
}

// headlineAge renders the most informative single age for the subject line.
//
// Durations are phrased as a noun phrase so that the caller can append "old"
// without producing nonsense like "just now old".
func headlineAge(c Candidate) string {
	if c.LaunchKnown {
		return "launched " + HumanizeAge(c.LaunchAge) + " ago"
	}
	if c.Fresh.FirstSeenAge > 0 {
		return "seen " + HumanizeAge(c.Fresh.FirstSeenAge) + " ago"
	}
	return ""
}

// triggerAge selects the age evidence that justifies the alert. Launch-triggered
// alerts use the source-reported launch age; change-triggered alerts use the
// bounded observation interval and never borrow the program's launch date.
func triggerAge(c Candidate, profile *config.Profile, now time.Time, trigger domain.AlertKind) string {
	switch trigger {
	case domain.AlertScopeExpansion, domain.AlertMaterialChange:
		observed := triggerObservation(c, trigger, profile, now)
		if observed.Known() {
			return observed.Humanize(now)
		}
		return "change timing unknown"
	default:
		return headlineAge(c)
	}
}

// HumanizeAge renders a duration as an age phrase.
//
// It differs from HumanizeDuration in that a sub-minute duration becomes a real
// quantity rather than the word "now", because "8m" and "2h" read correctly in a
// subject line where "just now old" does not.
func HumanizeAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "<1m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 365*24*time.Hour:
		days := int(d.Hours() / 24)
		if days < 30 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dmo", days/30)
	default:
		return fmt.Sprintf("%dy", int(d.Hours()/24)/365)
	}
}

// headlineSurface renders the most relevant surface for the subject line.
func headlineSurface(p domain.Program) string {
	targets := p.InScopeTargets()
	for _, kind := range []domain.TargetKind{domain.KindAPI, domain.KindWeb, domain.KindRepository} {
		if len(targets.OfKind(kind)) > 0 {
			switch kind {
			case domain.KindAPI:
				return "API/Web"
			case domain.KindWeb:
				return "Web"
			case domain.KindRepository:
				return "Code"
			}
		}
	}
	if len(p.SurfaceTags) > 0 {
		return p.SurfaceTags[0]
	}
	return ""
}

func displayName(p domain.Program) string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.Slug
}

// padRight pads a label to a fixed width so that score values align.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s + "  "
	}
	return s + strings.Repeat(" ", n-len(s))
}

func nonEmpty(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// writeField renders a labelled header field.
func writeField(b *strings.Builder, label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	b.WriteString(label + ": " + value + "\n")
}
