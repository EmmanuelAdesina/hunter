package hackenproof

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/source"
)

// fixtureServer serves captured pages from disk so that adapter behaviour is
// verified against real upstream output without touching the network.
type fixtureServer struct {
	mu    sync.Mutex
	pages map[string]string

	// requests records the paths served, in order.
	requests []string
}

// record appends a served path.
//
// The adapter fetches listing pages concurrently, so this counter is written from
// several goroutines. Guarding it here rather than in the assertion keeps the
// double honest about the concurrency the code under test actually has.
func (f *fixtureServer) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, path)
}

// requestCount reports how many requests have been served.
func (f *fixtureServer) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func newFixtureServer(t *testing.T, files map[string]string) *fixtureServer {
	t.Helper()
	pages := make(map[string]string, len(files))
	for route, file := range files {
		body, err := os.ReadFile(fixturePath(file))
		if err != nil {
			t.Fatalf("read fixture %s: %v", file, err)
		}
		pages[route] = string(body)
	}
	return &fixtureServer{pages: pages}
}

// doer returns a transport that serves the fixture pages.
func (f *fixtureServer) doer() source.HTTPDoer {
	return source.HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		path := req.URL.Path
		if q := req.URL.RawQuery; q != "" {
			path += "?" + q
		}
		f.record(path)
		body, ok := f.pages[path]
		if !ok {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     "404 Not Found",
				Body:       io.NopCloser(strings.NewReader("not found")),
				Header:     http.Header{},
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"text/html"}},
			Request:    req,
		}, nil
	})
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "fixtures", "hackenproof", name)
}

// newTestSource builds an adapter over a fixture transport with pacing
// disabled, so that tests neither sleep nor depend on wall-clock timing.
func newTestSource(t *testing.T, srv *fixtureServer, opts ...func(*Options)) *Source {
	t.Helper()
	cfg := source.ClientConfig{
		Timeout:        2 * time.Second,
		MaxRetries:     0,
		RetryBaseDelay: time.Millisecond,
		MaxRetryDelay:  2 * time.Millisecond,
		MinInterval:    0,
		MaxConcurrent:  4,
		UserAgent:      "hunter-test/1.0",
	}
	client := source.NewClient(cfg, srv.doer())
	o := Options{
		Client:          client,
		BaseURL:         "https://fixture.test",
		MaxPages:        1,
		PageConcurrency: 4,
		Now:             func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) },
	}
	for _, fn := range opts {
		fn(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// TestDiscoverFromListingFixture verifies discovery yields stable references.
//
// Identity is the load-bearing assertion: the platform exposes no durable
// program ID on the listing, so if slugs ever stopped being extracted every
// stored record would be orphaned and every program would look new.
func TestDiscoverFromListingFixture(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs": "listing-page1.html",
	})
	s := newTestSource(t, srv)

	refs, err := s.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(refs) < 5 {
		t.Fatalf("discovered %d references, want at least 5", len(refs))
	}

	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if r.ID == "" {
			t.Error("reference has no ID")
		}
		if seen[r.ID] {
			t.Errorf("duplicate reference %q", r.ID)
		}
		seen[r.ID] = true
		if r.Source != AdapterName {
			t.Errorf("source = %q, want %q", r.Source, AdapterName)
		}
		if !strings.HasPrefix(r.URL, "https://hackenproof.com/programs/") {
			t.Errorf("url = %q, want a public program URL", r.URL)
		}
	}
	t.Logf("discovered %d references, e.g. %s", len(refs), refs[0].ID)
}

// TestListingRowsReportMalformedEntriesWithoutDroppingValidPrograms verifies
// partial pages retain their valid references while surfacing the unreadable
// rows as a parse error.
func TestListingRowsReportMalformedEntriesWithoutDroppingValidPrograms(t *testing.T) {
	page := `<script id="__NUXT_DATA__">[{"data":1},{"programs-api-bounty":2},{"programs":3},[4,5],{"slug":6},null,"alpha"]</script>`
	refs, parseErr := ParseListingPage([]byte(page))
	if len(refs) != 1 || refs[0].ID != "alpha" {
		t.Fatalf("references = %+v, want the valid alpha row", refs)
	}
	if !errors.Is(parseErr, source.ErrParse) {
		t.Fatalf("parse error = %v, want ErrParse for the malformed row", parseErr)
	}

	srv := &fixtureServer{pages: map[string]string{"/programs": page}}
	s := newTestSource(t, srv)
	discovered, discoverErr := s.Discover(context.Background())
	if len(discovered) != 1 || discovered[0].ID != "alpha" {
		t.Fatalf("Discover references = %+v, want alpha despite the bad row", discovered)
	}
	if !errors.Is(discoverErr, source.ErrParse) {
		t.Fatalf("Discover error = %v, want the partial-page parse error", discoverErr)
	}
}

// TestMalformedListingIsNotTreatedAsEmpty verifies a non-empty list whose rows
// cannot be interpreted does not trigger the normal end-of-listing sentinel.
func TestMalformedListingIsNotTreatedAsEmpty(t *testing.T) {
	page := `<script id="__NUXT_DATA__">[{"data":1},{"programs-api-bounty":2},{"programs":3},[4],{"name":5},"no-slug"]</script>`
	refs, err := ParseListingPage([]byte(page))
	if err == nil || errors.Is(err, errNoProgramsOnPage) || !errors.Is(err, source.ErrParse) {
		t.Fatalf("ParseListingPage = (%+v, %v), want an ErrParse and not the empty-page sentinel", refs, err)
	}

	empty := `<script id="__NUXT_DATA__">[{"data":1},{"programs-api-bounty":2},{"programs":3},[]]</script>`
	refs, err = ParseListingPage([]byte(empty))
	if len(refs) != 0 || !errors.Is(err, errNoProgramsOnPage) {
		t.Fatalf("empty listing = (%+v, %v), want the normal empty-page sentinel", refs, err)
	}
}

// TestDiscoverStopsAtEndOfPagination verifies traversal terminates instead of
// looping, and that reaching the end of the listing is not treated as failure.
//
// Reporting a normal end-of-listing as an error would make every healthy run
// look degraded, which in turn invites an operator to ignore the warning that
// actually matters.
func TestDiscoverStopsAtEndOfPagination(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs": "listing-page1.html",
	})
	// Allow several batches so that traversal runs off the end of the real
	// listing and must stop on its own.
	s := newTestSource(t, srv, func(o *Options) { o.MaxPages = 12 })

	done := make(chan struct{})
	var refs []domain.ProgramRef
	var err error
	go func() {
		defer close(done)
		refs, err = s.Discover(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Discover did not terminate")
	}

	if err != nil {
		t.Errorf("reaching the end of the listing reported an error: %v", err)
	}
	if len(refs) == 0 {
		t.Error("references gathered before the end were discarded")
	}

	// Traversal must stop well short of the requested page budget, which is what
	// proves the end-of-listing rule fires rather than the ceiling.
	fetched := srv.requestCount()
	if fetched >= 12 {
		t.Errorf("fetched %d pages, want traversal to stop well before the ceiling", fetched)
	}
	if fetched > 6 {
		t.Errorf("fetched %d pages; the listing is one page plus its tail", fetched)
	}
	t.Logf("stopped after %d page requests", fetched)
}

// TestDiscoverRetainsListingFailures verifies that a transient listing error is
// not silently discarded as an ordinary end-of-pagination.
func TestDiscoverRetainsListingFailures(t *testing.T) {
	body, err := os.ReadFile(fixturePath("listing-page1.html"))
	if err != nil {
		t.Fatalf("read listing fixture: %v", err)
	}
	var mu sync.Mutex
	var requests int
	doer := source.HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requests++
		mu.Unlock()
		if req.URL.RawQuery == "" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(string(body))),
				Header:     http.Header{},
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Body:       io.NopCloser(strings.NewReader("unavailable")),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})
	client := source.NewClient(source.ClientConfig{
		Timeout:        time.Second,
		MaxRetries:     0,
		RetryBaseDelay: time.Millisecond,
		MaxRetryDelay:  2 * time.Millisecond,
		MaxConcurrent:  4,
		UserAgent:      "hunter-test/1.0",
	}, doer)
	s, err := New(Options{
		Client:          client,
		BaseURL:         "https://fixture.test",
		MaxPages:        8,
		PageConcurrency: 4,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	refs, err := s.Discover(context.Background())
	if len(refs) == 0 {
		t.Fatal("valid first-page references were discarded")
	}
	if !errors.Is(err, source.ErrUnavailable) {
		t.Fatalf("Discover error = %v, want ErrUnavailable for failed listing pages", err)
	}
	mu.Lock()
	gotRequests := requests
	mu.Unlock()
	if gotRequests >= 8 {
		t.Errorf("requested %d pages after repeated failures, want early stop", gotRequests)
	}
}

// TestFetchProgramFixture verifies the detail parser extracts the access facts
// policy depends on, from real upstream output.
// TestFetchCompletedProgramFixture verifies that a program which has left is
// read as closed rather than as live.
//
// The captured page is the CoinEx program two days after its end date: the
// page shows "Program left 2 days ago - Ended" and the submit control is
// disabled, while the payload's status field still reads "LIVE" because that
// field describes publication, not whether the program is running. The
// activity status is the field that answers the question that matters.
func TestFetchCompletedProgramFixture(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/coinex-web-and-mobile": "program-coinex-web-and-mobile.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "coinex-web-and-mobile", Slug: "coinex-web-and-mobile",
		URL: "https://hackenproof.com/programs/coinex-web-and-mobile",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !raw.Parsed {
		t.Fatalf("program not parsed: %v", raw.Issues)
	}
	if raw.Status != "LIVE" {
		t.Errorf("status = %q, want LIVE (the platform keeps publication separate from activity)", raw.Status)
	}
	if raw.ActivityStatus != "Completed" {
		t.Errorf("activity status = %q, want Completed", raw.ActivityStatus)
	}
	if raw.RawDates.End != "19 Oct 2026" {
		t.Errorf("end date = %q, want 19 Oct 2026", raw.RawDates.End)
	}
	if raw.RawDates.Unending {
		t.Error("a program with an end date must not be read as unending")
	}
}

// TestFetchProgramFixture verifies the standard program fixture is parsed.
func TestFetchProgramFixture(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/bitrue": "program-bitrue.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "bitrue", Slug: "bitrue",
		URL: "https://hackenproof.com/programs/bitrue",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !raw.Parsed {
		t.Fatalf("program not parsed: %v", raw.Issues)
	}
	if raw.Name != "Bitrue" {
		t.Errorf("name = %q, want Bitrue", raw.Name)
	}
	if raw.KYC != domain.TriNo {
		t.Errorf("KYC = %s, want no", raw.KYC)
	}
	if raw.POC != domain.TriYes {
		t.Errorf("POC = %s, want yes", raw.POC)
	}
	if raw.Reputation.Present != domain.TriYes || raw.Reputation.Points != 120 {
		t.Errorf("reputation = %s %d, want a 120-point requirement (the fixture's minReputation)",
			raw.Reputation.Present, raw.Reputation.Points)
	}
	if raw.Status == "" {
		t.Error("status was not extracted")
	}

	if len(raw.Scopes) == 0 {
		t.Fatal("no scopes extracted")
	}
	var haveWeb, haveAPI bool
	for _, sc := range raw.Scopes {
		if sc.Target == "" {
			t.Errorf("scope %q has no target", sc.Title)
		}
		switch sc.Title {
		case "Web":
			haveWeb = true
		case "API":
			haveAPI = true
		}
	}
	if !haveWeb || !haveAPI {
		t.Errorf("scopes web=%v api=%v, want both", haveWeb, haveAPI)
	}

	if raw.RawDates.Start == "" {
		t.Error("start date was not extracted")
	}
	if len(raw.CategoriesRaw) == 0 {
		t.Error("no category labels extracted")
	}
	t.Logf("scopes=%d categories=%v projectTypes=%v maxBounty=%s",
		len(raw.Scopes), raw.CategoriesRaw, raw.ProjectTypesRaw, raw.MaxBountyRaw)
}

// TestFetchKYCRequiredFixture verifies the KYC-required and contract-only case
// is read as such, since it is the input that must drive rejection.
func TestFetchKYCRequiredFixture(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/starknet-staking": "program-starknet-staking.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "starknet-staking", Slug: "starknet-staking",
		URL: "https://hackenproof.com/programs/starknet-staking",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.KYC != domain.TriYes {
		t.Errorf("KYC = %s, want yes", raw.KYC)
	}
	// The page states a 5-unit submission fee in the account's currency. A
	// non-zero fee must be reported as present with an unknown USD amount,
	// never as "no fee": reading it as absent once cleared a gated program
	// that charged for submissions.
	if raw.Fee.Present != domain.TriUnknown {
		t.Errorf("fee = %s, want present with unknown USD amount (the page's non-zero fee)", raw.Fee.Present)
	}
	// The page states a 150-point reputation requirement in minReputation.
	if raw.Reputation.Present != domain.TriYes || raw.Reputation.Points != 150 {
		t.Errorf("reputation = %s %d, want a 150-point requirement (the fixture's minReputation)",
			raw.Reputation.Present, raw.Reputation.Points)
	}
	if len(raw.Scopes) == 0 {
		t.Fatal("no scopes extracted")
	}
	sawContract := false
	for _, sc := range raw.Scopes {
		if sc.Title == "Smart Contract" {
			sawContract = true
		}
	}
	if !sawContract {
		t.Error("expected a Smart Contract scope")
	}
}

// TestFetchParseFailureIsNotSilent verifies a page the parser cannot read is
// reported as a parse failure.
//
// This is the single most important guarantee in the adapter: a parse failure
// must never degrade into an empty record, because an empty record flows into
// policy as "no reputation required, no fee, no KYC" and would be approved.
func TestFetchParseFailureIsNotSilent(t *testing.T) {
	cases := map[string]string{
		"no payload at all":        "<html><body>maintenance</body></html>",
		"truncated payload":        `<script id="__NUXT_DATA__">[[1,`,
		"payload not an array":     `<script id="__NUXT_DATA__">{"a":1}</script>`,
		"payload missing programs": `<script id="__NUXT_DATA__">[["Reactive",1],{"data":2},{"other":3},{"x":4},"v"]</script>`,
	}

	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			srv := &fixtureServer{pages: map[string]string{"/programs/x": page}}
			s := newTestSource(t, srv)

			raw, err := s.Fetch(context.Background(), domain.ProgramRef{
				Source: AdapterName, ID: "x", Slug: "x",
			})
			if err == nil {
				t.Fatalf("Fetch succeeded on an unreadable page (raw=%+v)", raw)
			}
			if !errors.Is(err, source.ErrParse) {
				t.Errorf("error = %v, want it to wrap ErrParse", err)
			}
			if raw.Parsed {
				t.Error("raw.Parsed is true for an unreadable page")
			}
		})
	}
}

// TestFetchPropagatesTransportFailures verifies upstream failures surface as
// retryable or terminal errors rather than as empty programs.
func TestFetchPropagatesTransportFailures(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		srv := &fixtureServer{pages: map[string]string{}}
		s := newTestSource(t, srv)
		_, err := s.Fetch(context.Background(), domain.ProgramRef{
			Source: AdapterName, ID: "gone", Slug: "gone",
		})
		if !errors.Is(err, source.ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
		if source.IsRetryable(err) {
			t.Error("a 404 must not be retryable")
		}
	})

	t.Run("server error is retryable", func(t *testing.T) {
		srv := &fixtureServer{pages: map[string]string{}}
		s := newTestSource(t, srv, func(o *Options) {
			o.Client = source.NewClient(source.ClientConfig{
				Timeout: time.Second, MaxRetries: 1, RetryBaseDelay: time.Millisecond,
			}, source.HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Status:     "503 Service Unavailable",
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     http.Header{},
					Request:    req,
				}, nil
			}))
		})
		_, err := s.Fetch(context.Background(), domain.ProgramRef{
			Source: AdapterName, ID: "x", Slug: "x",
		})
		if err == nil {
			t.Fatal("expected an error")
		}
		if !source.IsRetryable(err) {
			t.Errorf("error = %v, want it to be retryable", err)
		}
	})

	t.Run("rate limited is retryable", func(t *testing.T) {
		srv := &fixtureServer{pages: map[string]string{}}
		s := newTestSource(t, srv, func(o *Options) {
			o.Client = source.NewClient(source.ClientConfig{
				Timeout: time.Second, MaxRetries: 1, RetryBaseDelay: time.Millisecond,
			}, source.HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
				h := http.Header{}
				h.Set("Retry-After", "1")
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Status:     "429 Too Many Requests",
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     h,
					Request:    req,
				}, nil
			}))
		})
		_, err := s.Fetch(context.Background(), domain.ProgramRef{
			Source: AdapterName, ID: "x", Slug: "x",
		})
		if !errors.Is(err, source.ErrRateLimited) {
			t.Errorf("error = %v, want ErrRateLimited", err)
		}
		if !source.IsRetryable(err) {
			t.Error("429 must be retryable")
		}
	})
}

// TestNewValidatesConfiguration verifies misconfiguration fails at
// construction rather than at the first request.
func TestNewValidatesConfiguration(t *testing.T) {
	withClient := func() Options {
		return Options{Client: source.NewClient(source.ClientConfig{}, nil)}
	}

	if _, err := New(withClient()); err != nil {
		t.Errorf("bare options rejected: %v", err)
	}

	if _, err := New(Options{}); !errors.Is(err, source.ErrConfig) {
		t.Errorf("missing client accepted: %v", err)
	}

	o := withClient()
	o.DetailPathTemplate = "/programs/"
	if _, err := New(o); !errors.Is(err, source.ErrConfig) {
		t.Errorf("template without {slug} accepted: %v", err)
	}
}

// TestParsePlatformDateRejectsGarbage verifies an unrecognised date yields no
// date rather than the zero time.
func TestParsePlatformDateRejectsGarbage(t *testing.T) {
	if _, ok := parsePlatformDate(""); ok {
		t.Error("empty string parsed as a date")
	}
	if _, ok := parsePlatformDate("sometime last year"); ok {
		t.Error("prose parsed as a date")
	}
	got, ok := parsePlatformDate("28 Sep 2026")
	if !ok {
		t.Fatal("known format rejected")
	}
	if got.Year() != 2026 || got.Month() != time.September || got.Day() != 28 {
		t.Errorf("parsed %v, want 2026-09-28", got)
	}
}

// TestFetchFlipsterFixture pins a production incident: the Flipster program
// page demands 100 reputation points, but the adapter read the legacy
// reputationRequired key (always null) instead of minReputation and reported
// "no reputation required". Policy then approved a program the profile
// rejects, and an alert email repeated the false claim. This test replays the
// captured page and asserts every access fact the email stated.
func TestFetchFlipsterFixture(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/flipster-web-and-mobile": "program-flipster-web-and-mobile.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "flipster-web-and-mobile", Slug: "flipster-web-and-mobile",
		URL: "https://hackenproof.com/programs/flipster-web-and-mobile",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Reputation.Present != domain.TriYes || raw.Reputation.Points != 100 {
		t.Errorf("reputation = %s %d, want the page's 100-point requirement",
			raw.Reputation.Present, raw.Reputation.Points)
	}
	if raw.KYC != domain.TriNo {
		t.Errorf("KYC = %s, want no", raw.KYC)
	}
	if raw.POC != domain.TriYes {
		t.Errorf("POC = %s, want yes", raw.POC)
	}
	if raw.SubmittedReportsKnown != true || raw.SubmittedReports == nil || *raw.SubmittedReports != 114 {
		t.Errorf("submissions = %+v, want 114 reported", raw.SubmittedReports)
	}
	if raw.MaxBountyRaw == "" {
		t.Error("max bounty was not extracted")
	}
	if raw.RawDates.Start == "" {
		t.Error("start date was not extracted")
	}
}

// TestReputationGateResolution covers the minReputation contract directly:
// positive means gated, zero means observably gateless, and anything
// unreadable is unknown rather than silently approved.
func TestReputationGateResolution(t *testing.T) {
	cases := map[string]struct {
		fields  map[string]any
		present domain.Tri
		points  int
	}{
		"positive requirement": {
			fields:  map[string]any{"minReputation": 100.0},
			present: domain.TriYes, points: 100,
		},
		"zero means observably gateless": {
			fields:  map[string]any{"minReputation": 0.0},
			present: domain.TriNo,
		},
		"null requirement is unknown, not absent": {
			fields:  map[string]any{"minReputation": nil},
			present: domain.TriUnknown,
		},
		"absent requirement is unknown, not absent": {
			fields:  map[string]any{},
			present: domain.TriUnknown,
		},
		"non-numeric requirement is unknown": {
			fields:  map[string]any{"minReputation": "100"},
			present: domain.TriUnknown,
		},
		"legacy key is a fallback, not the source": {
			fields:  map[string]any{"minReputation": nil, "reputationRequired": 75.0},
			present: domain.TriYes, points: 75,
		},
		"legacy null with numeric requirement still resolves": {
			fields:  map[string]any{"minReputation": 50.0, "reputationRequired": nil},
			present: domain.TriYes, points: 50,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := reputationGate(tc.fields)
			if got.Present != tc.present || (tc.present == domain.TriYes && got.Points != tc.points) {
				t.Errorf("reputationGate(%v) = %s %d, want %s %d",
					tc.fields, got.Present, got.Points, tc.present, tc.points)
			}
		})
	}
}

// TestFeeGateResolution covers the submission-fee contract directly: a
// positive fee is present with an unknown USD amount, zero (number or string)
// is a positively observed absence, and anything unreadable is unknown rather
// than "none".
func TestFeeGateResolution(t *testing.T) {
	cases := map[string]struct {
		fields  map[string]any
		present domain.Tri
	}{
		"numeric fee is present, USD unknown": {
			fields:  map[string]any{"submissionFee": 5.0},
			present: domain.TriUnknown,
		},
		"zero number means no fee": {
			fields:  map[string]any{"submissionFee": 0.0},
			present: domain.TriNo,
		},
		"negative zero means no fee": {
			fields:  map[string]any{"submissionFee": math.Copysign(0, -1)},
			present: domain.TriNo,
		},
		"negative fee is unknown, not free": {
			fields:  map[string]any{"submissionFee": -3.0},
			present: domain.TriUnknown,
		},
		"NaN fee is unknown": {
			fields:  map[string]any{"submissionFee": math.NaN()},
			present: domain.TriUnknown,
		},
		"null means no fee": {
			fields:  map[string]any{"submissionFee": nil},
			present: domain.TriNo,
		},
		"absent field is unknown, not absent": {
			fields:  map[string]any{},
			present: domain.TriUnknown,
		},
		"zero string means no fee": {
			fields:  map[string]any{"submissionFee": "0"},
			present: domain.TriNo,
		},
		"numeric string is present, USD unknown": {
			fields:  map[string]any{"submissionFee": "5.00"},
			present: domain.TriUnknown,
		},
		"non-numeric string is present, USD unknown": {
			fields:  map[string]any{"submissionFee": "varies"},
			present: domain.TriUnknown,
		},
		"empty string means no fee": {
			fields:  map[string]any{"submissionFee": ""},
			present: domain.TriNo,
		},
		"uninterpretable value is unknown": {
			fields:  map[string]any{"submissionFee": true},
			present: domain.TriUnknown,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := feeGate(tc.fields)
			if got.Present != tc.present {
				t.Errorf("feeGate(%v) = %s, want %s", tc.fields, got.Present, tc.present)
			}
		})
	}
}

// TestPageMarkersReportWhatThePageShows verifies the human-visible lifecycle
// statements are captured verbatim.
//
// These are the only evidence of what a researcher sees when they open the
// page. A payload field can say a program is published while the page says it
// left two days ago, and the page is the one that settles whether a report
// can be submitted.
func TestPageMarkersReportWhatThePageShows(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/coinex-web-and-mobile": "program-coinex-web-and-mobile.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "coinex-web-and-mobile", Slug: "coinex-web-and-mobile",
		URL: "https://hackenproof.com/programs/coinex-web-and-mobile",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := raw.PageMarkers["liveness_badge"]; got != "Ended" {
		t.Errorf("liveness badge = %q, want Ended", got)
	}
	if got := raw.PageMarkers["program_left"]; got != "2 days ago" {
		t.Errorf("program left = %q, want 2 days ago", got)
	}
	if got := raw.PageMarkers["contest_notice"]; got != "not active" {
		t.Errorf("contest notice = %q, want not active", got)
	}
}

// A program that is still running shows no departure statement, and none is
// invented for it.
func TestPageMarkersAreAbsentForARunningProgram(t *testing.T) {
	srv := newFixtureServer(t, map[string]string{
		"/programs/bitrue": "program-bitrue.html",
	})
	s := newTestSource(t, srv)

	raw, err := s.Fetch(context.Background(), domain.ProgramRef{
		Source: AdapterName, ID: "bitrue", Slug: "bitrue",
		URL: "https://hackenproof.com/programs/bitrue",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(raw.PageMarkers) != 0 {
		t.Errorf("markers = %v, want none for a program that is still running", raw.PageMarkers)
	}
}
