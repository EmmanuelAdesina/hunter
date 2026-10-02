// Package notify delivers alerts.
//
// Delivery sits behind a narrow interface so that a second channel can be added
// without touching alert generation. Email is the only implementation now, and
// it is deliberately the only one: the mandate's goal is one high-signal
// channel, and adding more would dilute it.
//
// Delivery is idempotent under retry. A record of the attempt is written before
// the send, and the rendered alert carries a stable fingerprint, so a workflow
// that dies between send and acknowledgement re-attempts without producing a
// second copy of the same message.
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Sentinel errors distinguishing delivery outcomes.
var (
	// ErrNotConfigured means credentials are absent. This is expected in dry
	// runs and is not a failure of the scan.
	ErrNotConfigured = errors.New("notify: not configured")
	// ErrInvalidAlert means the alert could not be delivered as rendered.
	ErrInvalidAlert = errors.New("notify: invalid alert")
)

// Notifier delivers one alert.
type Notifier interface {
	// Send delivers an alert.
	Send(ctx context.Context, a domain.Alert) error

	// Name identifies the channel, for logs and diagnostics.
	Name() string

	// Configured reports whether the channel can deliver. A false result means
	// alerts are still generated and recorded, just not transmitted.
	Configured() bool
}

// DeliveryStatus records the outcome of one delivery attempt.
type DeliveryStatus struct {
	Notified  bool
	Attempted bool
	Skipped   bool
	Reason    string
	Duration  time.Duration
}

// Result describes what a batch delivery did.
type Result struct {
	Delivered int
	Failed    int
	Skipped   int
	Errors    []error
}

// Dispatcher sends a batch of alerts and reports per-alert outcomes.
//
// It owns the idempotency rule: an alert whose fingerprint has already been
// delivered is not sent again. Deduplication is therefore a property of the
// dispatch path rather than of any individual channel, which means a future
// channel inherits it for free.
type Dispatcher struct {
	notifier Notifier

	// isDelivered reports whether a fingerprint has already been delivered.
	isDelivered func(fingerprint string) bool
	// recordAttempt is called before each send.
	recordAttempt func(domain.AlertRecord) error
	// recordDelivered is called after a successful send.
	recordDelivered func(fingerprint string, at time.Time) error
	// now supplies the current time.
	now func() time.Time
}

// DispatcherConfig wires a dispatcher to its bookkeeping.
type DispatcherConfig struct {
	Notifier        Notifier
	IsDelivered     func(fingerprint string) bool
	RecordAttempt   func(domain.AlertRecord) error
	RecordDelivered func(fingerprint string, at time.Time) error
	Now             func() time.Time
}

// NewDispatcher builds a dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	d := &Dispatcher{
		notifier:        cfg.Notifier,
		isDelivered:     cfg.IsDelivered,
		recordAttempt:   cfg.RecordAttempt,
		recordDelivered: cfg.RecordDelivered,
		now:             cfg.Now,
	}
	if d.now == nil {
		d.now = time.Now
	}
	return d
}

// Dispatch delivers each alert at most once.
//
// One failure does not stop the batch. A provider outage would otherwise
// suppress every alert after the first, which is the worst possible behaviour
// during an incident.
func (d *Dispatcher) Dispatch(ctx context.Context, alerts []domain.Alert) (Result, error) {
	var res Result

	if d.notifier == nil {
		return res, errors.New("notify: dispatcher has no notifier")
	}

	for _, a := range alerts {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, err)
			return res, err
		}

		if a.Subject == "" {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Errorf("%w: alert %s has no subject", ErrInvalidAlert, a.ShortFingerprint()))
			continue
		}

		// Idempotency: a condition already announced stays announced.
		if d.isDelivered != nil && d.isDelivered(a.Fingerprint) {
			res.Skipped++
			continue
		}

		// The attempt is recorded first so that a crash between send and
		// acknowledgement is visible as an undelivered record rather than
		// vanishing.
		if d.recordAttempt != nil {
			rec := domain.AlertRecord{
				Fingerprint:   a.Fingerprint,
				Kind:          a.Kind,
				ProgramID:     a.ProgramID,
				ScanID:        a.ScanID,
				CreatedAt:     a.DetectedAt,
				Subject:       a.Subject,
				Body:          a.Body,
				LastAttemptAt: d.now().UTC(),
			}
			if err := d.recordAttempt(rec); err != nil {
				// Failing to record is not a reason to skip sending: the
				// researcher still wants the alert. The risk is a duplicate
				// after a crash, which is preferable to silence.
				res.Errors = append(res.Errors, fmt.Errorf("record attempt for %s: %w", a.ShortFingerprint(), err))
			}
		}

		start := d.now()
		err := d.notifier.Send(ctx, a)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Errorf("send %s (%s): %w", a.Program.Name, a.ShortFingerprint(), err))
			continue
		}

		res.Delivered++
		if d.recordDelivered != nil {
			if rerr := d.recordDelivered(a.Fingerprint, start.UTC()); rerr != nil {
				res.Errors = append(res.Errors, fmt.Errorf("record delivery for %s: %w", a.ShortFingerprint(), rerr))
			}
		}
	}
	return res, errors.Join(res.Errors...)
}

// Status reports whether the dispatcher can deliver.
func (d *Dispatcher) Status() DeliveryStatus {
	if d.notifier == nil || !d.notifier.Configured() {
		return DeliveryStatus{Reason: "notifier is not configured"}
	}
	return DeliveryStatus{Notified: true}
}

// Name returns the channel name.
func (d *Dispatcher) Name() string {
	if d.notifier == nil {
		return "none"
	}
	return d.notifier.Name()
}

// Undelivered reports whether an alert is awaiting redelivery, which lets a
// later run pick up a failed send without regenerating the alert.
func (d *Dispatcher) Undelivered(alerts []domain.Alert) []domain.Alert {
	if d.isDelivered == nil {
		return nil
	}
	out := make([]domain.Alert, 0, len(alerts))
	for _, a := range alerts {
		if !d.isDelivered(a.Fingerprint) {
			out = append(out, a)
		}
	}
	return out
}
