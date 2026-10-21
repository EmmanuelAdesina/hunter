package pipeline_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/pipeline"
	"github.com/eadeshina/hunter/internal/state"
	"github.com/eadeshina/hunter/internal/verify"
)

// stubVerifier answers with a fixed verdict.
type stubVerifier struct {
	result verify.Result
	err    error
	calls  int
	last   verify.Request
}

func (s *stubVerifier) Name() string { return "stub" }

func (s *stubVerifier) Verify(_ context.Context, req verify.Request) (verify.Result, error) {
	s.calls++
	s.last = req
	return s.result, s.err
}

// expandScope adds a new API asset, which is a change the profile alerts on.
func expandScope(src *fakeSource) {
	rec := src.records["alpha"]
	rec.Scopes = append(rec.Scopes, domain.RawScope{Title: "API", Target: "https://api-v2.alpha.example.com"})
	src.records["alpha"] = rec
	src.refs[0].Listing.RewardRaw = "$5,001"
}

// A program that qualifies and changes must reach the verifier, and the
// verifier's message must be the one delivered.
func TestVerifierMessageReplacesTheRenderedOne(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	v := &stubVerifier{result: verify.Result{
		Decision: verify.DecisionAllow,
		Reason:   "the evidence supports the change",
		Subject:  "Alpha now takes reports without a fee",
		Body:     "Alpha Web now takes reports without a submission fee. The page shows the program is live.",
		Claims: []verify.Claim{{
			Statement: "the program takes reports without a fee",
			Verdict:   verify.VerdictSupported,
			Evidence:  []string{"gate.submission_fee"},
		}},
	}}

	expandScope(src)
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Verifier = v
	})
	if err != nil {
		t.Fatal(err)
	}

	if v.calls == 0 {
		t.Fatal("the verifier was never asked")
	}
	if len(res.Alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(res.Alerts))
	}
	got := res.Alerts[0]
	if got.Subject != "Alpha now takes reports without a fee" {
		t.Errorf("subject = %q, want the verifier's subject", got.Subject)
	}
	if !strings.Contains(got.Body, "takes reports without a submission fee") {
		t.Errorf("body = %q, want the verifier's body", got.Body)
	}
	if got.HTMLBody != "" {
		t.Error("the rendered HTML body was kept alongside the verifier's message")
	}
	if got.Verification == nil {
		t.Fatal("the alert does not say it was verified")
	}
	if got.Verification.Verdict != string(verify.DecisionAllow) {
		t.Errorf("verification verdict = %q", got.Verification.Verdict)
	}
	if len(got.Verification.Claims) != 1 {
		t.Errorf("claims = %d, want the verifier's claims to be recorded", len(got.Verification.Claims))
	}

	// The record that is kept must carry the same message and the same
	// verification, so that what was believed and why cannot drift apart.
	var recorded bool
	for _, rec := range recordedAlerts(t, dir) {
		if rec.Subject != got.Subject {
			continue
		}
		recorded = true
		if rec.Verification == nil {
			t.Fatal("the stored record does not say it was verified")
		}
		if rec.Verification.Verdict != string(verify.DecisionAllow) {
			t.Errorf("stored verdict = %q", rec.Verification.Verdict)
		}
	}
	if !recorded {
		t.Error("the verified message was not stored")
	}
}

// A verifier that withholds the alert must keep the alert from being
// delivered, and the reason must be recorded.
func TestVerifierCanWithholdAnAlert(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	v := &stubVerifier{result: verify.Result{
		Decision: verify.DecisionSuppress,
		Reason:   "the page says the program left, so the change is not real",
	}}

	expandScope(src)
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Verifier = v
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Alerts) != 0 {
		t.Errorf("alerts = %d, want none", len(res.Alerts))
	}
	if res.Metrics.AlertsSuppressed == 0 {
		t.Error("the withheld alert was not counted as suppressed")
	}
}

// The evidence the verifier receives must contain what it needs to judge the
// claim.
func TestVerifierReceivesTheObservedFacts(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	v := &stubVerifier{result: verify.Result{Decision: verify.DecisionSuppress, Reason: "not now"}}
	expandScope(src)
	if _, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Verifier = v
	}); err != nil {
		t.Fatal(err)
	}

	if v.last.Program.Name == "" {
		t.Error("the verifier received no program")
	}
	if v.last.Now.IsZero() {
		t.Error("the verifier received no observation time")
	}
	if v.last.Decision.Eligible && len(v.last.Decision.Reasons) == 0 {
		t.Error("the verifier received an eligibility decision with no reasons")
	}
}

// A verifier that fails outright must not let the alert through.
func TestVerifierFailureWithholdsTheAlert(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	v := &stubVerifier{err: context.DeadlineExceeded}
	expandScope(src)
	res, err := runScanner(t, src, dir, func(c *pipeline.Config) {
		c.Verifier = v
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Alerts) != 0 {
		t.Errorf("alerts = %d, want none when the verifier fails", len(res.Alerts))
	}
}

// Without a verifier the pipeline behaves as it did before.
func TestNoVerifierKeepsTheRenderedMessage(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	expandScope(src)
	res, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) == 0 {
		t.Skip("the fake source produced no alert to check")
	}
	if res.Alerts[0].Verification != nil {
		t.Error("an alert was recorded as verified although no verifier ran")
	}
	_ = time.Now
}

// recordedAlerts reads the alert records the scan wrote.
func recordedAlerts(t *testing.T, dir string) []domain.AlertRecord {
	t.Helper()
	records, err := state.NewFileStore(dir).ListAlerts(context.Background(), 0)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	return records
}
