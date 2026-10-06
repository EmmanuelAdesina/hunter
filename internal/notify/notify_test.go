package notify_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/notify"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// recordingNotifier captures alerts and can be made to fail.
type recordingNotifier struct {
	mu         sync.Mutex
	sent       []domain.Alert
	err        error
	configured bool
}

func (n *recordingNotifier) Send(_ context.Context, a domain.Alert) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.sent = append(n.sent, a)
	return nil
}

func (n *recordingNotifier) Name() string     { return "recording" }
func (n *recordingNotifier) Configured() bool { return n.configured }
func (n *recordingNotifier) count() int       { n.mu.Lock(); defer n.mu.Unlock(); return len(n.sent) }

func alertFor(id string) domain.Alert {
	return domain.Alert{
		Fingerprint: "fp-" + id,
		Kind:        domain.AlertNewQualifying,
		ProgramID:   "hackenproof:" + id,
		ScanID:      "scan1",
		Subject:     "[HUNTER] NEW MATCH — " + id,
		Body:        "body for " + id + "\n",
		DetectedAt:  fixedNow,
	}
}

type bookkeeping struct {
	mu         sync.Mutex
	attempts   map[string]int
	delivered  map[string]time.Time
	attemptErr error
	deliverErr error

	// attemptHook and deliverHook let a test override behaviour while still
	// recording through the default bookkeeping.
	attemptHook func(domain.AlertRecord) error
	deliverHook func(string, time.Time) error
}

func newBookkeeping() *bookkeeping {
	return &bookkeeping{
		attempts:  map[string]int{},
		delivered: map[string]time.Time{},
	}
}

func (b *bookkeeping) isDelivered(fp string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.delivered[fp]
	return ok
}

func (b *bookkeeping) recordAttempt(rec domain.AlertRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.attemptHook != nil {
		return b.attemptHook(rec)
	}
	if b.attemptErr != nil {
		return b.attemptErr
	}
	b.attempts[rec.Fingerprint]++
	return nil
}

func (b *bookkeeping) recordDelivered(fp string, at time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deliverHook != nil {
		return b.deliverHook(fp, at)
	}
	if b.deliverErr != nil {
		return b.deliverErr
	}
	b.delivered[fp] = at
	return nil
}

func newDispatcherFor(t *testing.T, n notify.Notifier) (*notify.Dispatcher, *bookkeeping) {
	t.Helper()
	book := newBookkeeping()
	return notify.NewDispatcher(notify.DispatcherConfig{
		Notifier:        n,
		IsDelivered:     book.isDelivered,
		RecordAttempt:   book.recordAttempt,
		RecordDelivered: book.recordDelivered,
		Now:             func() time.Time { return fixedNow },
	}), book
}

// TestDispatchDelivers verifies a straightforward send.
func TestDispatchDelivers(t *testing.T) {
	n := &recordingNotifier{configured: true}
	d, _ := newDispatcherFor(t, n)

	res, err := d.Dispatch(context.Background(), []domain.Alert{alertFor("a")})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.Delivered != 1 || n.count() != 1 {
		t.Errorf("delivered=%d sent=%d, want 1 and 1", res.Delivered, n.count())
	}
}

// TestDispatchIsIdempotent verifies an already-delivered alert is not sent
// again. This is what protects the channel when a workflow retries.
func TestDispatchIsIdempotent(t *testing.T) {
	n := &recordingNotifier{configured: true}
	d, _ := newDispatcherFor(t, n)
	ctx := context.Background()
	alert := alertFor("a")

	if _, err := d.Dispatch(ctx, []domain.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	res, err := d.Dispatch(ctx, []domain.Alert{alert})
	if err != nil {
		t.Fatal(err)
	}
	if n.count() != 1 {
		t.Errorf("alert sent %d times, want exactly once", n.count())
	}
	if res.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 on the repeat send", res.Skipped)
	}
}

// TestDeliveryBookkeepingFailureIsReturned verifies a successful SMTP send
// cannot hide a failed persisted acknowledgement.
func TestDeliveryBookkeepingFailureReturnedEvenWhenSendSucceeds(t *testing.T) {
	n := &recordingNotifier{configured: true}
	d, book := newDispatcherFor(t, n)
	book.deliverErr = errors.New("state store unavailable")

	res, err := d.Dispatch(context.Background(), []domain.Alert{alertFor("ack-failure")})
	if err == nil {
		t.Fatal("Dispatch reported success after delivery bookkeeping failed")
	}
	if res.Delivered != 1 || n.count() != 1 {
		t.Errorf("delivered=%d sent=%d, want one successful send", res.Delivered, n.count())
	}
	if res.Failed != 0 {
		t.Errorf("failed = %d, want 0 because the notifier send succeeded", res.Failed)
	}
	if book.isDelivered("fp-ack-failure") {
		t.Error("failed delivery acknowledgement was recorded as delivered")
	}
}

// TestOneFailureDoesNotStopTheBatch verifies a provider outage does not
// suppress every later alert.
func TestOneFailureDoesNotStopTheBatch(t *testing.T) {
	n := &recordingNotifier{configured: true, err: errors.New("smtp unavailable")}
	d, _ := newDispatcherFor(t, n)

	res, err := d.Dispatch(context.Background(), []domain.Alert{
		alertFor("a"), alertFor("b"), alertFor("c"),
	})
	if err == nil {
		t.Error("Dispatch reported success despite a failing notifier")
	}
	if res.Failed != 3 {
		t.Errorf("failed = %d, want 3", res.Failed)
	}
	if len(res.Errors) != 3 {
		t.Errorf("recorded %d errors, want 3", len(res.Errors))
	}
}

// TestFailedAlertIsNotMarkedDelivered verifies a failure leaves the alert
// retryable, so a later run re-sends it rather than losing it.
func TestFailedAlertIsNotMarkedDelivered(t *testing.T) {
	book := newBookkeeping()
	flaky := &flakyNotifier{failFirst: true}
	d := notify.NewDispatcher(notify.DispatcherConfig{
		Notifier:        flaky,
		IsDelivered:     book.isDelivered,
		RecordAttempt:   book.recordAttempt,
		RecordDelivered: book.recordDelivered,
		Now:             func() time.Time { return fixedNow },
	})
	ctx := context.Background()
	alert := alertFor("a")

	res, _ := d.Dispatch(ctx, []domain.Alert{alert})
	if res.Delivered != 0 {
		t.Fatal("a failing send was counted as delivered")
	}
	if book.isDelivered(alert.Fingerprint) {
		t.Error("a failed send was marked delivered, which would lose the alert")
	}

	// The retry must succeed and be recorded.
	res, _ = d.Dispatch(ctx, []domain.Alert{alert})
	if res.Delivered != 1 {
		t.Errorf("retry delivered = %d, want 1", res.Delivered)
	}
	if !book.isDelivered(alert.Fingerprint) {
		t.Error("a successful retry was not recorded as delivered")
	}
	if book.attempts[alert.Fingerprint] != 2 {
		t.Errorf("attempts = %d, want 2", book.attempts[alert.Fingerprint])
	}
}

// flakyNotifier fails its first send and then succeeds.
type flakyNotifier struct {
	mu        sync.Mutex
	failFirst bool
	failed    bool
}

func (f *flakyNotifier) Name() string     { return "flaky" }
func (f *flakyNotifier) Configured() bool { return true }
func (f *flakyNotifier) Send(_ context.Context, _ domain.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFirst && !f.failed {
		f.failed = true
		return errors.New("temporary failure")
	}
	return nil
}

// TestAttemptIsRecordedBeforeSend verifies the ordering that makes a crash
// recoverable: the attempt is written first, so an interrupted run leaves a
// visible pending record rather than nothing at all.
func TestAttemptIsRecordedBeforeSend(t *testing.T) {
	book := newBookkeeping()
	var order []string
	book.attemptHook = func(rec domain.AlertRecord) error {
		order = append(order, "attempt:"+rec.Fingerprint)
		book.attempts[rec.Fingerprint]++
		return nil
	}
	book.deliverHook = func(fp string, at time.Time) error {
		order = append(order, "delivered:"+fp)
		book.delivered[fp] = at
		return nil
	}
	n := &orderNotifier{onSend: func() { order = append(order, "send") }}
	d := notify.NewDispatcher(notify.DispatcherConfig{
		Notifier:        n,
		IsDelivered:     book.isDelivered,
		RecordAttempt:   book.recordAttempt,
		RecordDelivered: book.recordDelivered,
		Now:             func() time.Time { return fixedNow },
	})
	if _, err := d.Dispatch(context.Background(), []domain.Alert{alertFor("a")}); err != nil {
		t.Fatal(err)
	}
	want := []string{"attempt:fp-a", "send", "delivered:fp-a"}
	if len(order) != len(want) {
		t.Fatalf("call order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, order[i], want[i])
		}
	}
}

type orderNotifier struct {
	onSend func()
}

func (o *orderNotifier) Name() string     { return "order" }
func (o *orderNotifier) Configured() bool { return true }
func (o *orderNotifier) Send(_ context.Context, _ domain.Alert) error {
	o.onSend()
	return nil
}

// TestRecordFailureStillSends verifies a bookkeeping failure does not silence a
// real alert. The worst outcome is a duplicate after a crash; the alternative is
// an opportunity the researcher never hears about.
func TestRecordFailureStillSends(t *testing.T) {
	book := newBookkeeping()
	book.attemptErr = errors.New("disk full")
	n := &recordingNotifier{configured: true}
	d := notify.NewDispatcher(notify.DispatcherConfig{
		Notifier:        n,
		IsDelivered:     book.isDelivered,
		RecordAttempt:   book.recordAttempt,
		RecordDelivered: book.recordDelivered,
		Now:             func() time.Time { return fixedNow },
	})

	if _, err := d.Dispatch(context.Background(), []domain.Alert{alertFor("a")}); err == nil {
		t.Error("the bookkeeping failure was not reported")
	}
	if n.count() != 1 {
		t.Error("a bookkeeping failure suppressed the alert")
	}
}

// TestUndeliveredReportsPendingAlerts verifies pending alerts are discoverable
// so a later run can retry them.
func TestUndeliveredReportsPendingAlerts(t *testing.T) {
	book := newBookkeeping()
	book.delivered["fp-b"] = fixedNow
	n := &recordingNotifier{configured: true}
	d := notify.NewDispatcher(notify.DispatcherConfig{
		Notifier:        n,
		IsDelivered:     book.isDelivered,
		RecordAttempt:   book.recordAttempt,
		RecordDelivered: book.recordDelivered,
		Now:             func() time.Time { return fixedNow },
	})

	pending := d.Undelivered([]domain.Alert{alertFor("a"), alertFor("b"), alertFor("c")})
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	for _, a := range pending {
		if a.Fingerprint == "fp-b" {
			t.Error("a delivered alert was reported as pending")
		}
	}
}

// TestUnconfiguredNotifierIsReported verifies an absent configuration is visible
// rather than silently skipping delivery.
func TestUnconfiguredNotifierIsReported(t *testing.T) {
	d := newDispatcherOrPanic(t, &recordingNotifier{configured: false})
	if d.Status().Notified {
		t.Error("an unconfigured notifier reported itself as ready")
	}
	if !strings.Contains(d.Status().Reason, "not configured") {
		t.Errorf("reason = %q, want it to explain the missing configuration", d.Status().Reason)
	}
}

func newDispatcherOrPanic(t *testing.T, n notify.Notifier) *notify.Dispatcher {
	t.Helper()
	d, _ := newDispatcherFor(t, n)
	return d
}

// TestCancelledContextStopsDispatch verifies a cancelled run stops promptly.
func TestCancelledContextStopsDispatch(t *testing.T) {
	n := &recordingNotifier{configured: true}
	d, _ := newDispatcherFor(t, n)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := d.Dispatch(ctx, []domain.Alert{alertFor("a"), alertFor("b")})
	if err == nil {
		t.Error("a cancelled dispatch reported success")
	}
	if n.count() != 0 {
		t.Error("an alert was sent after cancellation")
	}
	_ = res
}

// TestInvalidAlertIsRejected verifies an alert with no subject is refused
// rather than sent as an empty message.
func TestInvalidAlertIsRejected(t *testing.T) {
	n := &recordingNotifier{configured: true}
	d, _ := newDispatcherFor(t, n)

	bad := alertFor("a")
	bad.Subject = ""
	res, _ := d.Dispatch(context.Background(), []domain.Alert{bad})
	if res.Failed != 1 {
		t.Errorf("failed = %d, want 1", res.Failed)
	}
	if n.count() != 0 {
		t.Error("an alert with no subject was sent")
	}
}

// TestSMTPConfigRequiresEveryValue verifies partial credentials are treated as
// absent configuration rather than as a half-working setup.
func TestSMTPConfigRequiresEveryValue(t *testing.T) {
	full := notify.SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		Username: "a@example.com", Password: "x", Recipient: "b@example.com",
	}
	if !full.Configured() {
		t.Error("a complete configuration reported itself incomplete")
	}
	partials := []notify.SMTPConfig{
		{Port: 587, Username: "a", Password: "x", Recipient: "b"},
		{Host: "h", Username: "a", Password: "x", Recipient: "b"},
		{Host: "h", Port: 587, Password: "x", Recipient: "b"},
		{Host: "h", Port: 587, Username: "a", Recipient: "b"},
		{Host: "h", Port: 587, Username: "a", Password: "x"},
	}
	for i, c := range partials {
		if c.Configured() {
			t.Errorf("partial configuration %d reported itself complete", i)
		}
	}
}

// TestSMTPDescribeNeverLeaksSecrets verifies diagnostics are safe to log.
func TestSMTPDescribeNeverLeaksSecrets(t *testing.T) {
	cfg := notify.SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		Username: "a@example.com", Password: "super-secret",
		Recipient: "b@example.com",
	}
	got := cfg.Describe()
	for _, secret := range []string{"super-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Describe leaked a credential: %q", got)
		}
	}
	if !strings.Contains(got, "auth=true") || !strings.Contains(got, "recipient_set=true") {
		t.Errorf("Describe = %q, want it to report presence as flags", got)
	}
}

// TestUnconfiguredNotifierRefusesToSend verifies delivery fails loudly rather
// than silently doing nothing.
func TestUnconfiguredNotifierRefusesToSend(t *testing.T) {
	n := notify.NewSMTPNotifier(notify.SMTPConfig{}, time.Second)
	if n.Configured() {
		t.Fatal("an empty configuration reported itself complete")
	}
	err := n.Send(context.Background(), alertFor("a"))
	if !errors.Is(err, notify.ErrNotConfigured) {
		t.Errorf("error = %v, want ErrNotConfigured", err)
	}
}
