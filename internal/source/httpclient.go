package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientConfig tunes HTTP behaviour for a source.
type ClientConfig struct {
	// Timeout bounds a single request including its body read.
	Timeout time.Duration

	// MaxRetries is the number of retries after the initial attempt. A value
	// of 3 means at most 4 requests.
	MaxRetries int

	// RetryBaseDelay is the first backoff delay. Each further retry doubles
	// it up to MaxRetryDelay.
	RetryBaseDelay time.Duration

	// MaxRetryDelay caps exponential backoff.
	MaxRetryDelay time.Duration

	// MinInterval is the minimum spacing between requests to this source. It
	// is what keeps a five-minute scan a polite client rather than a load.
	MinInterval time.Duration

	// UserAgent identifies the client. It must be stable and truthful.
	UserAgent string

	// MaxConcurrent bounds simultaneous requests.
	MaxConcurrent int
}

// Client is an HTTP client with bounded retries, exponential backoff, and rate
// control.
//
// The transport is injectable so that failure paths - timeouts, 429, 500,
// truncated bodies - can be tested deterministically instead of being exercised
// against a live service.
type Client struct {
	cfg      ClientConfig
	hc       HTTPDoer
	sleep    func(ctx context.Context, d time.Duration) error
	interval time.Duration

	mu   sync.Mutex
	last time.Time

	sem chan struct{}
}

// HTTPDoer is the transport contract, satisfied by *http.Client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPDoerFunc adapts a function to HTTPDoer.
type HTTPDoerFunc func(req *http.Request) (*http.Response, error)

// Do implements HTTPDoer.
func (f HTTPDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// defaultMaxBodyBytes caps how much of a response is read. A listing page for
// this source is a few hundred kilobytes; the limit exists to bound memory if a
// response is malformed or hostile, not to truncate legitimate pages.
const defaultMaxBodyBytes = 8 << 20

// NewClient builds a client from configuration, applying defaults.
func NewClient(cfg ClientConfig, doer HTTPDoer) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = time.Second
	}
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = 30 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "hunter-research-monitor/1.0"
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 2
	}
	if doer == nil {
		doer = &http.Client{
			Transport: newTransport(cfg),
			Timeout:   cfg.Timeout,
		}
	}

	return &Client{
		cfg:      cfg,
		hc:       doer,
		sleep:    sleepCtx,
		interval: cfg.MinInterval,
		sem:      make(chan struct{}, cfg.MaxConcurrent),
	}
}

// newTransport builds an HTTP transport tuned for this workload.
//
// The non-default values matter in practice. Go's stock ten-second TLS
// handshake timeout is short enough to fail against a high-latency path, and a
// retry storm against a third-party site is worse than a patient one. Pooling
// matters more still: a scan touches many pages on one host, and paying a fresh
// handshake for each of them is what turns a two-minute job into a twenty-minute
// one.
func newTransport(cfg ClientConfig) *http.Transport {
	// The handshake may legitimately take as long as the whole request budget,
	// so it is bounded by that rather than by a separate, smaller default.
	handshake := cfg.Timeout
	if handshake <= 0 {
		handshake = 20 * time.Second
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   handshake,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   handshake,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		// Compression is left enabled so that the transport negotiates and
		// decodes it transparently. Setting Accept-Encoding by hand would
		// disable that, leaving the caller with undecoded bytes.
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}
}

// GetWithContext fetches a URL and returns the response body.
//
// Retries cover transient failures only. A 404, a 403, or a parse failure is
// returned immediately: retrying those would hammer the source without any
// prospect of a different answer.
func (c *Client) GetWithContext(ctx context.Context, url string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.backoff(attempt, lastErr)
			if err := c.sleep(ctx, delay); err != nil {
				return nil, fmt.Errorf("backoff interrupted: %w", errors.Join(lastErr, err))
			}
		}

		if err := c.waitForSlot(ctx); err != nil {
			return nil, err
		}

		body, err := c.attempt(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err

		if !IsRetryable(err) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, errors.Join(lastErr, ctx.Err())
		}
	}
	return nil, fmt.Errorf("giving up after %d retries: %w", c.cfg.MaxRetries, lastErr)
}

// attempt performs one request.
func (c *Client) attempt(ctx context.Context, url string) ([]byte, error) {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	// Accept-Encoding is deliberately not set: the transport adds it and decodes
	// the response automatically. Setting it here would switch that off and hand
	// back compressed bytes, which would then fail to parse for no visible
	// reason.
	req.Header.Set("Accept-Language", "en")

	resp, err := c.hc.Do(req)
	if err != nil {
		// Transport failures are transient by nature; classify them so the
		// retry loop can act.
		if errors.Is(err, context.Canceled) {
			return nil, errors.Join(context.Canceled, err)
		}
		return nil, &HTTPStatusError{Status: "transport error", URL: url, Err: errors.Join(ErrUnavailable, err)}
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxBodyBytes))
		if err != nil {
			return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status, URL: url, Err: errors.Join(ErrUnavailable, err)}
		}
		return body, nil
	}

	return nil, classifyStatus(resp, url)
}

// classifyStatus maps a non-2xx response onto a sentinel error.
func classifyStatus(resp *http.Response, url string) error {
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	e := &HTTPStatusError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		URL:        url,
		RetryAfter: retryAfter,
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		e.Err = ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		e.Err = ErrRateLimited
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Access controls are respected, not worked around. These are
		// terminal, and the adapter reports them as unavailable so the scan
		// degrades rather than escalating.
		e.Err = ErrUnavailable
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout:
		e.Err = ErrUnavailable
	default:
		e.Err = fmt.Errorf("%w: unexpected status", ErrParse)
	}
	return e
}

// parseRetryAfter interprets either supported Retry-After form: delta-seconds
// or an HTTP-date. An unparseable, absent, or already elapsed value yields zero,
// which leaves the exponential backoff in charge.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs > 0 {
		const maxDuration = time.Duration(1<<63 - 1)
		maxSeconds := int64(maxDuration / time.Second)
		if secs > maxSeconds {
			return maxDuration
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if delay := time.Until(at); delay > 0 {
			return delay
		}
	}
	return 0
}

// backoff returns the delay before the given attempt.
//
// The exponential delay doubles each time and is capped. When the source sent a
// Retry-After header, that instruction wins over the computed delay and the local
// cap: retrying sooner would disregard an explicit access control.
func (c *Client) backoff(attempt int, lastErr error) time.Duration {
	if attempt < 1 {
		return 0
	}

	d := c.cfg.RetryBaseDelay
	for i := 1; i < attempt; i++ {
		if d >= c.cfg.MaxRetryDelay || d > c.cfg.MaxRetryDelay/2 {
			d = c.cfg.MaxRetryDelay
			break
		}
		d *= 2
	}

	var se *HTTPStatusError
	if errors.As(lastErr, &se) && se.RetryAfter > 0 {
		if se.RetryAfter > d {
			d = se.RetryAfter
		}
		// Retry-After is an explicit server instruction. Do not cap it back
		// down to the local exponential-backoff ceiling and retry prematurely.
		return d
	}
	if d > c.cfg.MaxRetryDelay {
		d = c.cfg.MaxRetryDelay
	}
	return d
}

// waitForSlot enforces the minimum spacing between requests.
//
// The source is a third-party service and this system is a guest on it. A
// five-minute sweep touching several hundred pages must not look like an attack,
// so pacing is enforced here rather than trusted to callers.
//
// Slots are reserved under the lock rather than re-checked after sleeping. A
// check-then-sleep loop lets concurrent waiters wake together, lose the race,
// and sleep again, which quietly turns a fixed spacing into a much larger one
// and serializes requests that were meant to overlap. Reserving the slot and
// sleeping until it gives every request a distinct, already-committed time.
func (c *Client) waitForSlot(ctx context.Context) error {
	if c.interval <= 0 {
		return nil
	}

	c.mu.Lock()
	now := time.Now()
	slot := now
	if !c.last.IsZero() {
		if earliest := c.last.Add(c.interval); earliest.After(now) {
			slot = earliest
		}
	}
	c.last = slot
	wait := slot.Sub(now)
	c.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	return c.sleep(ctx, wait)
}

// sleepCtx waits for d unless the context ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
