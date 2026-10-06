package normalize

import (
	"strconv"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Options tune normalization.
type Options struct {
	// Now supplies the current time, so normalization is deterministic in
	// tests.
	Now func() time.Time

	// DateLayouts lists the formats accepted for source dates, tried in order.
	// Dates are never guessed: an unrecognised value yields no date.
	DateLayouts []string
}

// DefaultDateLayouts covers the day-resolution formats the source uses.
var DefaultDateLayouts = []string{
	"02 Jan 2006",
	"2 Jan 2006",
	"Jan 2, 2006",
	"2006-01-02",
	"2006-01-02T15:04:05Z07:00",
	time.RFC3339,
}

// dateLayoutsFor returns the layouts to use, falling back to the defaults.
func (o Options) dateLayoutsFor() []string {
	if len(o.DateLayouts) == 0 {
		return DefaultDateLayouts
	}
	return o.DateLayouts
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// Program converts an adapter record into the canonical model.
//
// The converter never invents a fact. Every value it cannot read is left in its
// unknown state and the reason is appended to ParseIssues, which policy uses to
// quarantine rather than to approve.
func Program(raw domain.RawProgram, opts Options) domain.Program {
	now := opts.now()
	issues := append([]string(nil), raw.Issues...)

	p := domain.Program{
		ID:                    raw.Ref.Key(),
		Source:                raw.Ref.Source,
		Slug:                  firstNonEmpty(raw.Ref.Slug, raw.Ref.ID),
		Name:                  strings.TrimSpace(raw.Name),
		URL:                   raw.URL,
		RawStatus:             raw.Status,
		RawState:              raw.State,
		IsUnending:            raw.RawDates.Unending,
		Reputation:            raw.Reputation,
		Fee:                   raw.Fee,
		KYC:                   raw.KYC,
		POC:                   raw.POC,
		SubmittedReports:      raw.SubmittedReports,
		SubmittedReportsKnown: raw.SubmittedReportsKnown,
		Summary:               raw.Description,
		ScopeNotes:            raw.ScopeNotes,
		ProgramRules:          raw.Rules,
		FirstSeenAt:           now,
		LastSeenAt:            now,
	}

	if p.Source == "" {
		p.Source = "unknown"
	}
	if p.Slug == "" {
		issues = append(issues, "program has no identifier")
	}
	if p.Name == "" {
		issues = append(issues, "program has no name")
	}
	if !raw.Parsed {
		issues = append(issues, "source record was not parsed")
	}

	p.State = normalizeState(raw)
	p.StartedAt = parseDate(raw.RawDates.Start, opts.dateLayoutsFor())
	if p.StartedAt == nil {
		// Absent launch date is normal on some platforms. It is not an error,
		// but it does mean program age cannot be established from the source,
		// so first-observation age is used instead.
	}
	if end := parseDate(raw.RawDates.End, opts.dateLayoutsFor()); end != nil {
		p.EndsAt = end
	}
	if upd := parseDate(raw.RawDates.Updated, opts.dateLayoutsFor()); upd != nil {
		p.SourceUpdatedAt = upd
	}
	if p.State == domain.StateEnded && p.EndsAt == nil && !p.IsUnending {
		p.State = domain.StateEnded
	}

	p.MinBountyUSD = parseMoney(raw.MinBountyRaw)
	p.MaxBountyUSD = parseMoney(raw.MaxBountyRaw)
	p.RewardsPaidUSD = parseMoney(raw.RewardsPaidRaw)

	p.Categories = domain.NewTags(raw.CategoriesRaw...)
	p.ProjectTypes = domain.NewTags(raw.ProjectTypesRaw...)
	p.Technologies = domain.NewTags(raw.TechnologiesRaw...)
	p.Languages = domain.NewTags(raw.LanguagesRaw...)

	p.Targets = normalizeTargets(raw.Scopes, &issues)

	// Classification runs over normalized inputs so that it sees exactly what
	// policy will see.
	kinds := make([]domain.TargetKind, 0, len(p.Targets))
	for _, tgt := range p.Targets {
		if !tgt.InScope {
			continue
		}
		kinds = append(kinds, tgt.Kind)
	}
	scopeText := buildScopeText(p.Targets)
	crypto := classifyCrypto(cryptoInput{
		ProjectTypes: p.ProjectTypes,
		Categories:   p.Categories,
		ScopeText:    scopeText,
		Description:  p.Summary,
		ScopeNotes:   p.ScopeNotes,
		TargetKinds:  kinds,
	})
	p.CryptoKind = crypto.Kind
	p.CryptoTraits = crypto.Traits.Tags()
	p.SurfaceTags = surfaceTags(kinds)
	p.CapabilityTags = capabilityTags(scopeText + " " + p.ScopeNotes + " " + p.Summary)

	// Access-critical facts decide trust. If any of them is unknown, the
	// record is downgraded so that policy quarantines it by default.
	p.ParseConfidence = assessConfidence(p, raw.Parsed)
	p.ParseIssues = domain.NewTags(issues...).Clone()

	p.Finalize()
	return p
}

// normalizeState maps the source's lifecycle vocabulary onto a domain state.
//
// Unknown vocabulary is preserved in RawStatus and mapped to StateUnknown
// rather than being optimistically read as live: a program whose state the
// system cannot interpret must not be assumed to be accepting reports.
func normalizeState(raw domain.RawProgram) domain.ProgramState {
	switch strings.ToUpper(strings.TrimSpace(raw.Status)) {
	case "NEW":
		return domain.StateNew
	case "LIVE":
		return domain.StateLive
	case "PAUSED":
		return domain.StatePaused
	case "ENDED", "CLOSED", "ARCHIVED":
		return domain.StateEnded
	case "UNLISTED", "DRAFT", "HIDDEN":
		return domain.StateUnlisted
	case "":
		// Fall through to the state field.
	default:
		return domain.StateUnknown
	}

	switch strings.ToLower(strings.TrimSpace(raw.State)) {
	case "published":
		return domain.StateLive
	case "draft":
		return domain.StateUnlisted
	case "unlisted":
		return domain.StateUnlisted
	case "archived", "closed":
		return domain.StateEnded
	default:
		return domain.StateUnknown
	}
}

// normalizeTargets converts source assets into canonical targets.
//
// An asset's kind is taken from its title when the title is recognized, and
// inferred from the identifier otherwise. When both are available the title
// wins, because a program calling an asset "API" means it even when the host
// looks like a website.
func normalizeTargets(scopes []domain.RawScope, issues *[]string) domain.Targets {
	out := make(domain.Targets, 0, len(scopes))
	for _, sc := range scopes {
		kind, ok := domain.KindOfTitle(sc.Title)
		if !ok {
			kind = domain.InferTargetKind(sc.Target)
			if kind == domain.KindOther && sc.Title == "" {
				*issues = append(*issues, "asset with an unrecognized title and identifier was skipped")
				continue
			}
		}
		out = append(out, domain.Target{
			Kind:        kind,
			Identifier:  sc.Target,
			Label:       sc.Title,
			Description: sc.Description,
			InScope:     !sc.OutOfScope,
			SourceID:    sc.ID,
		})
	}
	return out
}

// buildScopeText concatenates the scope titles and descriptions for
// classification.
func buildScopeText(targets domain.Targets) string {
	parts := make([]string, 0, len(targets)*2)
	for _, t := range targets {
		if !t.InScope {
			continue
		}
		if t.Label != "" {
			parts = append(parts, t.Label)
		}
		if t.Identifier != "" {
			parts = append(parts, t.Identifier)
		}
		if t.Description != "" {
			parts = append(parts, t.Description)
		}
	}
	return strings.Join(parts, " \n ")
}

// parseDate parses a date string, returning nil when it cannot be read.
//
// A nil result is meaningful: the caller reports program age from first
// observation instead of inventing a launch date.
func parseDate(raw string, layouts []string) *time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}

// parseMoney parses a decimal money string.
//
// The source expresses bounty bounds as decimal strings such as "1500.0".
// Values that cannot be parsed yield nil rather than zero, because a zero
// bounty and an unreadable bounty mean different things.
func parseMoney(raw string) *float64 {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	// Tolerate currency symbols and thousands separators the display layer
	// sometimes adds.
	s = strings.NewReplacer("$", "", ",", "", "USD", "", "usd", "").Replace(s)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return nil
	}
	return &v
}

// assessConfidence decides how much the record can be trusted.
//
// Access gates are the deciding factor. A program whose KYC requirement or
// reputation requirement could not be read is low confidence, and policy will
// quarantine it unless the profile explicitly opts in. Getting this wrong in
// the permissive direction would let a parser regression approve every program
// on the platform.
func assessConfidence(p domain.Program, parsed bool) domain.Confidence {
	// A record the adapter could not parse is low confidence regardless of what
	// its individual fields happen to say. The individual fields may look
	// complete while the surrounding structure was not understood, and treating
	// that as trustworthy is exactly the failure this system must not have.
	if !parsed {
		return domain.ConfidenceLow
	}
	if p.Slug == "" || p.Name == "" {
		return domain.ConfidenceLow
	}
	criticalUnknown := !p.KYC.Known() ||
		!p.Reputation.Known() ||
		!p.Fee.Known() ||
		p.State == domain.StateUnknown
	if criticalUnknown {
		return domain.ConfidenceLow
	}
	if len(p.Targets) == 0 || p.MaxBountyUSD == nil {
		return domain.ConfidencePartial
	}
	return domain.ConfidenceHigh
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
