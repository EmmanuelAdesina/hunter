package source

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetRetriesTransportFailures(t *testing.T) {
	calls := 0
	doer := HTTPDoerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("temporary connection reset")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})
	client := NewClient(ClientConfig{
		Timeout:        time.Second,
		MaxRetries:     2,
		RetryBaseDelay: time.Millisecond,
		MaxRetryDelay:  2 * time.Millisecond,
		MaxConcurrent:  1,
	}, doer)
	client.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	body, err := client.GetWithContext(context.Background(), "https://fixture.test/programs")
	if err != nil {
		t.Fatalf("GetWithContext: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
	if calls != 2 {
		t.Errorf("transport calls = %d, want 2 including the retry", calls)
	}
}

func TestRetryAfterIsNotCappedByExponentialLimit(t *testing.T) {
	client := NewClient(ClientConfig{
		RetryBaseDelay: time.Second,
		MaxRetryDelay:  5 * time.Second,
	}, nil)
	err := &HTTPStatusError{
		StatusCode: http.StatusTooManyRequests,
		RetryAfter: 10 * time.Second,
		Err:        ErrRateLimited,
	}
	if got := client.backoff(1, err); got != 10*time.Second {
		t.Errorf("backoff = %s, want to honor Retry-After of 10s", got)
	}
}

func TestParseRetryAfterAcceptsHTTPDate(t *testing.T) {
	want := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	got := parseRetryAfter(want.Format(http.TimeFormat))
	if got <= 0 {
		t.Errorf("parsed HTTP-date delay = %s, want a positive delay", got)
	}
}
