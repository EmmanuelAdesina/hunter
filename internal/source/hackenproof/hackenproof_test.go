package hackenproof

import (
	"context"
	"errors"
	"io"
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

// TestFetchProgramFixture verifies the detail parser extracts the access facts
// policy depends on, from real upstream output.
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
	if raw.Reputation.Present != domain.TriNo {
		t.Errorf("reputation = %s, want a positively observed absence of a gate", raw.Reputation.Present)
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
