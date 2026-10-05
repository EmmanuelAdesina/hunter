// Package hackenproof implements the HackenProof public program source.
//
// The platform renders its program pages on the server and embeds the data as
// a flattened reference payload in the HTML. There is no public JSON API, so
// that payload is the machine-readable form of information the platform already
// publishes to every visitor.
//
// Design constraints this adapter upholds:
//   - It reads only what an unauthenticated visitor receives. It has no
//     credentials, no cookie jar, and no mechanism for defeating rate limits,
//     bot protection, or any other access control.
//   - Every field that could not be read confidently is left unknown rather
//     than defaulted. A missing access gate must never look like an absent one.
//   - Discovery and detail retrieval are separate. The listing carries no
//     access-gate data, so gating decisions require a detail fetch, and the
//     caller decides which programs deserve one.
package hackenproof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/source"
	"github.com/eadeshina/hunter/internal/source/devalue"
)

// AdapterName is the registry key for this source.
const AdapterName = "hackenproof"

// Defaults for the endpoints this adapter reads. Overridable through profile
// configuration so that a future layout change is a configuration edit.
const (
	DefaultBaseURL        = "https://hackenproof.com"
	DefaultListPath       = "/programs"
	DefaultDetailTemplate = "/programs/{slug}"

	// programPathPrefix is the stable public URL prefix for a program page.
	programPathPrefix = "/programs/"
)

// Options configures the adapter.
type Options struct {
	// Client performs HTTP requests with retry and pacing.
	Client *source.Client

	// BaseURL is the site root.
	BaseURL string

	// ListPath is the listing path.
	ListPath string

	// DetailPathTemplate is the detail path, with a {slug} placeholder.
	DetailPathTemplate string

	// PerPage is the listing page size requested.
	PerPage int

	// MaxPages bounds listing traversal. Zero traverses to the end.
	MaxPages int

	// PageConcurrency is how many listing pages are fetched in parallel.
	// Request pacing still applies to every individual request.
	PageConcurrency int

	// Now supplies the current time, so that tests are deterministic.
	Now func() time.Time
}

// Source is the HackenProof adapter.
type Source struct {
	opts Options
}

// compile-time check that the adapter satisfies the source contract.
var _ domain.ProgramSource = (*Source)(nil)

// New builds the adapter.
func New(opts Options) (*Source, error) {
	if opts.Client == nil {
		return nil, fmt.Errorf("%w: hackenproof requires an HTTP client", source.ErrConfig)
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.ListPath == "" {
		opts.ListPath = DefaultListPath
	}
	if opts.DetailPathTemplate == "" {
		opts.DetailPathTemplate = DefaultDetailTemplate
	}
	if !strings.Contains(opts.DetailPathTemplate, "{slug}") {
		return nil, fmt.Errorf("%w: detail path template must contain {slug}", source.ErrConfig)
	}
	if opts.PerPage <= 0 {
		opts.PerPage = 10
	}
	if opts.PageConcurrency <= 0 {
		// Defaulted from the adapter's own declared concurrency rather than from a
		// literal, so that raising the declared limit is enough to change the
		// behaviour here. A separate magic number is how the two drifted apart.
		opts.PageConcurrency = capabilities().MaxConcurrent
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Source{opts: opts}, nil
}

// Name returns the adapter identifier.
func (s *Source) Name() string { return AdapterName }

// capabilities is the adapter's declared limit set, as a value rather than a
// literal, so the defaults below and the reported capabilities cannot disagree.
func capabilities() domain.SourceCapabilities {
	return domain.SourceCapabilities{
		MaxConcurrent:            2,
		MinRequestInterval:       750 * time.Millisecond,
		HasStableIDs:             false,
		SupportsIncrementalFetch: false,
		DetailFields: []string{
			"slug", "title", "status", "state", "kycRequired", "pocRequired",
			"reputationRequired", "submissionFee", "minBounty", "maxBounty",
			"scopes", "labels", "startDate", "endDate", "submittedReports",
		},
	}
}

// Capabilities describes the adapter's limits.
//
// HasStableIDs is false because the platform's own program identifiers are
// absent from the public listing and change across renames; the slug is the
// durable key. SupportsIncrementalFetch is false because the listing's update
// marker has day resolution, which cannot gate detail fetches without missing
// same-day changes.
// These limits govern EVERY request this adapter makes, listing pages included.
//
// That was not true until the listing sweep was brought under them. The adapter
// advertised 750ms and two-at-a-time while discovery fanned out four listing pages
// at the profile's 400ms, so the sweep ran roughly three times hotter than the
// adapter's own stated tolerance - which is how a routine scan ends in HTTP 429
// and silently loses a tenth of the catalogue. A declared capability that the
// adapter does not honour is worse than none, because callers trust it.
func (s *Source) Capabilities() domain.SourceCapabilities { return capabilities() }

// listingPaths returns the listing URLs to traverse.
//
// Traversal stops when a page returns no new programs or the configured page
// cap is reached. Both guards exist because the listing is paginated with a
// cursor the HTML does not expose directly.
func (s *Source) listingPaths() []string {
	base := s.opts.BaseURL + s.opts.ListPath
	pages := []string{base}
	if s.opts.MaxPages > 0 {
		for p := 2; p <= s.opts.MaxPages; p++ {
			pages = append(pages, base+"?page="+strconv.Itoa(p))
		}
		return pages
	}
	// Unbounded traversal is capped by a hard ceiling so that a pagination
	// change which repeats page 1 forever cannot loop indefinitely. The
	// observed listing is well under this.
	const hardPageCeiling = 200
	for p := 2; p <= hardPageCeiling; p++ {
		pages = append(pages, base+"?page="+strconv.Itoa(p))
	}
	return pages
}

// Discover lists the programs visible on the listing pages.
//
// Pages are fetched in ordered batches rather than one at a time. A full sweep
// touches thirty-odd pages, and doing that sequentially made a scan take
// minutes; batching lets the request run in parallel while the client still
// paces every individual request. Order is preserved within a batch so that the
// end-of-listing rule stays exact.
//
// Partial failure is deliberate. If page three fails, the references recovered
// so far are still returned together with the error, so a transient outage
// narrows coverage instead of producing an empty scan that would look like
// "nothing new" and suppress alerts.
func (s *Source) Discover(ctx context.Context) ([]domain.ProgramRef, error) {
	var (
		refs []domain.ProgramRef
		errs []error
		seen = make(map[string]struct{})

		unproductive int
	)

	batch := s.opts.PageConcurrency
	if batch <= 0 {
		batch = 4
	}
	paths := s.listingPaths()

	type pageResult struct {
		refs []domain.ProgramRef
		err  error
	}

	for start := 0; start < len(paths); start += batch {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		end := start + batch
		if end > len(paths) {
			end = len(paths)
		}

		// Pagination past the end of the listing is normal, not a failure. Once
		// traversal has clearly passed the end, errors from that tail are
		// dropped: reporting them would make every healthy run look broken and
		// would mask a genuine failure earlier in the traversal.
		tailStart := len(errs)

		results := make([]pageResult, len(paths[start:end]))
		var wg sync.WaitGroup
		for i, path := range paths[start:end] {
			wg.Add(1)
			go func(i int, path string) {
				defer wg.Done()
				body, err := s.opts.Client.GetWithContext(ctx, path)
				if err != nil {
					results[i] = pageResult{err: err}
					return
				}
				pageRefs, err := s.parseListing(body)
				results[i] = pageResult{refs: pageRefs, err: err}
			}(i, path)
		}
		wg.Wait()

		for i, r := range results {
			path := paths[start+i]
			if r.err != nil {
				// An empty page is the listing ending, not a fault. It advances the
				// unproductive counter and nothing else, so a scan that walked off
				// the end of the catalogue still reports a clean result.
				if !errors.Is(r.err, errNoProgramsOnPage) {
					errs = append(errs, fmt.Errorf("listing %s: %w", path, r.err))
				}
				unproductive++
				if unproductive >= unproductivePageLimit {
					errs = errs[:tailStart]
					return refs, joinErrors(errs)
				}
				continue
			}

			fresh := 0
			for _, ref := range r.refs {
				if _, dup := seen[ref.ID]; dup {
					continue
				}
				seen[ref.ID] = struct{}{}
				refs = append(refs, ref)
				fresh++
			}
			if fresh == 0 {
				unproductive++
				if unproductive >= unproductivePageLimit {
					errs = errs[:tailStart]
					return refs, joinErrors(errs)
				}
				continue
			}
			unproductive = 0
		}
	}

	if len(refs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("%w: no programs discovered: %w", source.ErrUnavailable, joinErrors(errs))
	}
	return refs, joinErrors(errs)
}

// parseListing extracts program references from one listing page.
func (s *Source) parseListing(body []byte) ([]domain.ProgramRef, error) {
	doc, err := decodePayload(body)
	if err != nil {
		return nil, err
	}

	programs, ok := devalue.Find(doc.Root, "data", "programs-api-bounty", "programs")
	if !ok {
		return nil, fmt.Errorf("%w: listing payload has no programs-api-bounty.programs", source.ErrParse)
	}
	list, ok := devalue.AsSlice(programs)
	if !ok {
		return nil, fmt.Errorf("%w: listing programs is %T, want a list", source.ErrParse, programs)
	}

	out := make([]domain.ProgramRef, 0, len(list))
	for i, item := range list {
		m, ok := devalue.AsMap(item)
		if !ok {
			// A single unreadable entry must not lose the rest of the page.
			continue
		}
		ref, ok := refFromListing(m)
		if !ok {
			continue
		}
		_ = i
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil, errNoProgramsOnPage
	}
	return out, nil
}

// refFromListing builds a reference from one listing entry.
//
// The slug is the identity. The platform's own identifier is not exposed here,
// and reconstructing identity from a name would make a rename look like a new
// program.
func refFromListing(m map[string]any) (domain.ProgramRef, bool) {
	slug := strings.TrimSpace(devalue.AsString(m["slug"]))
	if slug == "" {
		return domain.ProgramRef{}, false
	}
	ref := domain.ProgramRef{
		Source: AdapterName,
		ID:     slug,
		Slug:   slug,
		Name:   strings.TrimSpace(devalue.AsString(m["name"])),
		URL:    DefaultBaseURL + programPathPrefix + slug,
	}

	// The listing's submission count is a useful early competition signal, but
	// only when it is actually present. Absence is tracked separately.
	if n, ok := devalue.AsInt(m["submittedReports"]); ok && n >= 0 {
		v := n
		ref.SubmittedReports = &v
		ref.SubmittedReportsKnown = true
	}
	if updated, ok := parsePlatformDate(devalue.AsString(m["lastUpdated"])); ok {
		t := updated
		ref.ListingUpdatedAt = &t
	}

	// Everything the listing alone exposes is captured here. It is enough to
	// detect a new program or an upstream change without fetching the detail
	// page, which is what makes a five-minute sweep affordable.
	listing := domain.Listing{
		UpdatedAt:             ref.ListingUpdatedAt,
		Status:                strings.TrimSpace(devalue.AsString(m["status"])),
		State:                 strings.TrimSpace(devalue.AsString(m["state"])),
		RewardRaw:             strings.TrimSpace(devalue.AsString(m["reward"])),
		RewardsPaidRaw:        strings.TrimSpace(devalue.AsString(m["rewardPaid"])),
		Unending:              boolValue(m["isUnending"]),
		SubmittedReports:      ref.SubmittedReports,
		SubmittedReportsKnown: ref.SubmittedReportsKnown,
	}
	if v, ok := devalue.AsNumber(m["scopeReview"]); ok {
		listing.RenderCounter = int(v)
	}
	if activity, ok := devalue.AsMap(m["activityStatus"]); ok {
		listing.ActivityStatus = strings.TrimSpace(devalue.AsString(activity["name"]))
	}
	listing.Categories = tagStrings(m["tags"], "types")
	listing.ProjectTypes = tagStrings(m["tags"], "project_types")
	listing.Technologies = tagStrings(m["tags"], "platforms")
	ref.Listing = listing

	return ref, true
}

// tagStrings reads a nested list of classification labels from a tag object.
func tagStrings(node devalue.Node, key string) []string {
	m, ok := devalue.AsMap(node)
	if !ok {
		return nil
	}
	list, ok := devalue.AsSlice(m[key])
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s := strings.TrimSpace(devalue.AsString(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Fetch retrieves one program's public record.
func (s *Source) Fetch(ctx context.Context, ref domain.ProgramRef) (domain.RawProgram, error) {
	slug := ref.Slug
	if slug == "" {
		slug = ref.ID
	}
	url := s.opts.BaseURL + strings.Replace(s.opts.DetailPathTemplate, "{slug}", slug, 1)

	body, err := s.opts.Client.GetWithContext(ctx, url)
	if err != nil {
		return domain.RawProgram{Ref: ref}, err
	}

	raw, err := s.parseProgram(body, ref)
	if err != nil {
		raw.Ref = ref
		return raw, err
	}
	return raw, nil
}

// parseProgram extracts the raw program record from a detail page.
func (s *Source) parseProgram(body []byte, ref domain.ProgramRef) (domain.RawProgram, error) {
	doc, err := decodePayload(body)
	if err != nil {
		return domain.RawProgram{Ref: ref}, err
	}

	node, ok := devalue.Find(doc.Root, "data", "program")
	if !ok {
		return domain.RawProgram{Ref: ref}, fmt.Errorf("%w: detail payload has no data.program", source.ErrParse)
	}
	m, ok := firstProgramMap(node)
	if !ok {
		return domain.RawProgram{Ref: ref}, fmt.Errorf("%w: data.program is %T", source.ErrParse, node)
	}

	raw := domain.RawProgram{
		Ref:         ref,
		Parsed:      true,
		Name:        strings.TrimSpace(devalue.AsString(m["title"])),
		URL:         ref.URL,
		Status:      strings.TrimSpace(devalue.AsString(m["status"])),
		State:       strings.TrimSpace(devalue.AsString(m["state"])),
		Description: strings.TrimSpace(devalue.AsString(m["description"])),
		ScopeNotes:  strings.TrimSpace(devalue.AsString(m["focusArea"])),
		Rules:       strings.TrimSpace(devalue.AsString(m["programRules"])),
	}

	if raw.Name == "" {
		raw.Name = ref.Name
	}
	if raw.Name == "" {
		raw.Issues = append(raw.Issues, "program has no title")
	}

	raw.KYC = boolTri(m["kycRequired"])
	raw.POC = boolTri(m["pocRequired"])

	// An absent reputation requirement is a real, meaningful state: the
	// program does not gate on reputation. It is only left unknown when the
	// field's container itself is missing, which means the layout changed.
	raw.Reputation = reputationGate(m)
	raw.Fee = feeGate(m)

	raw.MinBountyRaw = numericString(m["minBounty"])
	raw.MaxBountyRaw = numericString(m["maxBounty"])
	raw.RewardsPaidRaw = numericString(m["totalRewards"])

	if n, ok := devalue.AsInt(m["submittedReports"]); ok && n >= 0 {
		v := n
		raw.SubmittedReports = &v
		raw.SubmittedReportsKnown = true
	}

	raw.RawDates = domain.RawDates{
		Start:    strings.TrimSpace(devalue.AsString(m["startDate"])),
		End:      strings.TrimSpace(devalue.AsString(m["endDate"])),
		Updated:  strings.TrimSpace(devalue.AsString(m["lastUpdated"])),
		Unending: boolValue(m["isUnending"]),
	}

	raw.CategoriesRaw = labelsOf(m, "types")
	raw.ProjectTypesRaw = labelsOf(m, "project_types")
	raw.TechnologiesRaw = labelsOf(m, "platforms")
	raw.LanguagesRaw = labelsOf(m, "languages")

	raw.Scopes = parseScopes(m["scopes"])

	return raw, nil
}

// parseScopes reads the asset list.
func parseScopes(node devalue.Node) []domain.RawScope {
	list, ok := devalue.AsSlice(node)
	if !ok {
		return nil
	}
	out := make([]domain.RawScope, 0, len(list))
	for _, item := range list {
		m, ok := devalue.AsMap(item)
		if !ok {
			continue
		}
		scope := domain.RawScope{
			Title:       strings.TrimSpace(devalue.AsString(m["title"])),
			Target:      strings.TrimSpace(devalue.AsString(m["target"])),
			Description: strings.TrimSpace(devalue.AsString(m["target_description"])),
			Criticality: strings.TrimSpace(devalue.AsString(m["criticality"])),
			ID:          strings.TrimSpace(devalue.AsString(m["id"])),
		}
		if v, ok := devalue.AsBool(m["out_of_scope"]); ok {
			scope.OutOfScope = v
		}
		// An asset with neither a label nor an identifier carries no
		// information and would pollute fingerprints.
		if scope.Target == "" && scope.Title == "" {
			continue
		}
		out = append(out, scope)
	}
	return out
}

// boolTri converts a decoded value into a tri-state, preserving absence.
func boolTri(node devalue.Node) domain.Tri {
	v, ok := devalue.AsBool(node)
	if !ok {
		return domain.TriUnknown
	}
	return domain.TriOf(v)
}

func boolValue(node devalue.Node) bool {
	v, _ := devalue.AsBool(node)
	return v
}

// reputationGate reads the reputation requirement.
//
// The platform expresses "no reputation required" by omitting the field, which
// decodes to an absent value. That is reported as a positively observed absence
// of a gate, because the surrounding program object was parsed successfully.
// Only a missing program object leaves it unknown.
func reputationGate(m map[string]any) domain.ReputationGate {
	node, present := m["reputationRequired"]
	if !present || node == nil {
		return domain.ReputationGate{Present: domain.TriNo}
	}
	if n, ok := devalue.AsInt(node); ok {
		if n <= 0 {
			return domain.ReputationGate{Present: domain.TriNo}
		}
		return domain.ReputationGate{Present: domain.TriYes, Points: n}
	}
	return domain.ReputationGate{Present: domain.TriUnknown}
}

// feeGate reads the submission fee, which is expressed in the account's
// currency rather than USD. It is left unknown rather than assumed zero,
// because a fee the researcher cannot see is a fee they may be unwilling to
// pay.
func feeGate(m map[string]any) domain.FeeGate {
	node, present := m["submissionFee"]
	if !present {
		return domain.FeeGate{Present: domain.TriUnknown}
	}
	if node == nil {
		return domain.FeeGate{Present: domain.TriNo}
	}
	s := strings.TrimSpace(devalue.AsString(node))
	if s == "" {
		return domain.FeeGate{Present: domain.TriNo}
	}
	// A non-zero fee cannot be converted to USD without the platform's
	// exchange rate, so it is reported as an unknown USD amount rather than
	// an invented figure.
	return domain.FeeGate{Present: domain.TriUnknown}
}

// numericString reads a monetary field, which the platform expresses as a
// decimal string.
func numericString(node devalue.Node) string {
	if node == nil {
		return ""
	}
	if s := devalue.AsString(node); s != "" {
		return strings.TrimSpace(s)
	}
	if f, ok := devalue.AsNumber(node); ok {
		return devalue.FormatNumber(f)
	}
	return ""
}

// labelsOf reads one nested list of classification labels.
func labelsOf(m map[string]any, key string) []string {
	labels, ok := devalue.AsMap(m["labels"])
	if !ok {
		return nil
	}
	list, ok := devalue.AsSlice(labels[key])
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s := devalue.AsString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// firstProgramMap extracts the program object, tolerating the single-element
// wrapper list the renderer sometimes uses.
func firstProgramMap(node devalue.Node) (map[string]any, bool) {
	switch typed := node.(type) {
	case map[string]any:
		return typed, true
	case []any:
		if len(typed) == 0 {
			return nil, false
		}
		m, ok := devalue.AsMap(typed[0])
		return m, ok
	default:
		return nil, false
	}
}

// decodePayload extracts and decodes the embedded payload.
func decodePayload(body []byte) (*devalue.Document, error) {
	payload, err := devalue.ExtractPayload(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", source.ErrParse, err)
	}
	doc, err := devalue.Decode(payload, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", source.ErrParse, err)
	}
	return doc, nil
}

// platformDateLayouts covers the day-resolution date format the listing uses.
// Detail pages use the same format for start and end dates.
var platformDateLayouts = []string{"02 Jan 2006", "2 Jan 2006", "Jan 2, 2006", "2006-01-02"}

// parsePlatformDate parses a platform date string.
//
// The format has varied between day-first and month-first spellings, so
// several layouts are tried and an unrecognised value yields no date at all.
// Returning zero time here would be read as "launched at the epoch" and would
// make every program look decades old.
func parsePlatformDate(v string) (time.Time, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range platformDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// joinErrors combines collected errors while preserving nil.
//
// Discovery accumulates one error per failed page and needs to report them
// together, since a partially completed sweep is not the same as a single
// failure and the operator wants to see both.
func joinErrors(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}

// ParseListingPage extracts program references from a captured listing page.
//
// It is exported so that fixture-based verification exercises exactly the same
// parsing code as a live scan. A test that reimplemented the parser would prove
// nothing about the parser that actually runs.
func ParseListingPage(body []byte) ([]domain.ProgramRef, error) {
	doc, err := decodePayload(body)
	if err != nil {
		return nil, err
	}

	programs, ok := devalue.Find(doc.Root, "data", "programs-api-bounty", "programs")
	if !ok {
		return nil, fmt.Errorf("%w: listing payload has no programs-api-bounty.programs", source.ErrParse)
	}
	list, ok := devalue.AsSlice(programs)
	if !ok {
		return nil, fmt.Errorf("%w: listing programs is %T, want a list", source.ErrParse, programs)
	}

	out := make([]domain.ProgramRef, 0, len(list))
	for _, item := range list {
		m, ok := devalue.AsMap(item)
		if !ok {
			continue
		}
		if ref, ok := refFromListing(m); ok {
			out = append(out, ref)
		}
	}
	if len(out) == 0 {
		return nil, errNoProgramsOnPage
	}
	return out, nil
}

// ParseProgramPage extracts a program record from a captured detail page.
//
// The reference supplies identity only; everything else is read from the page.
func ParseProgramPage(body []byte, ref domain.ProgramRef) (domain.RawProgram, error) {
	return (&Source{}).parseProgram(body, ref)
}

// errNoProgramsOnPage reports a listing page that parsed cleanly but contained no
// programs.
//
// It is deliberately not a parse failure. Pagination past the end of a listing is
// normal, and reporting it as an error makes every healthy scan report errors>0
// and exit non-zero, which trains an operator to ignore failures and destroys the
// signal the exit code exists to carry.
var errNoProgramsOnPage = errors.New("listing page contains no programs")

// unproductivePageLimit is how many consecutive pages may contribute nothing new
// before traversal is considered finished.
//
// Two is enough to distinguish "the listing ended" from "one page was odd",
// because pagination past the end is consistently empty. Counting unreadable
// pages towards the limit matters: without it, a listing that ends in a
// different shape than expected would be traversed all the way to the hard
// ceiling on every single scan.
const unproductivePageLimit = 2

// FetchPage retrieves one page body. It exists so that diagnostics and tooling
// can inspect the source without duplicating transport setup.
func FetchPage(hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hunter-diagnostic/1.0")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
