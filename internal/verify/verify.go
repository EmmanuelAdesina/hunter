// Package verify gates alerts behind an independent reader.
//
// The pipeline's own comparison says that something changed. That comparison
// is mechanical, and mechanical comparisons are only as good as the facts
// they are given: a platform that reports a program as published while its
// page says the program left two days ago produces a confident, well
// formatted, entirely false alert.
//
// This package asks a second reader - a language model - to check the claimed
// change against the evidence that was actually observed, and to write the
// notification itself when the claim holds. The model is not allowed to
// soften a claim it cannot support: an unsupported statement is a
// suppression, not a hedged sentence. Every statement in a delivered message
// must carry the evidence key it came from, and a message that cites nothing
// is not delivered.
//
// The gate is fail-closed. If the model is unreachable, if it returns
// something that is not the agreed shape, or if it claims a verdict it does
// not support, the alert is withheld.
package verify

import (
	"context"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// Decision is the verifier's verdict on one candidate alert.
type Decision string

const (
	// DecisionAllow means the evidence supports the change and the message may
	// be delivered.
	DecisionAllow Decision = "allow"

	// DecisionSuppress means the alert is withheld. The reason is recorded so
	// that a withheld alert can be audited rather than merely missing.
	DecisionSuppress Decision = "suppress"
)

// Claim is one statement the message makes.
//
// A claim carries the evidence keys it rests on. The keys must exist in the
// bundle that was sent, which is what makes the citation checkable rather
// than decorative.
type Claim struct {
	// Statement is the assertion as it appears in the message.
	Statement string `json:"statement"`

	// Verdict is the reader's own assessment of that statement: supported,
	// contradicted, or unverifiable.
	Verdict string `json:"verdict"`

	// Evidence lists the evidence keys the statement rests on.
	Evidence []string `json:"evidence"`
}

// Verdicts a claim may carry.
const (
	VerdictSupported    = "supported"
	VerdictContradicted = "contradicted"
	VerdictUnverifiable = "unverifiable"
)

// Result is the verifier's verdict and, when the alert may be delivered, the
// message to deliver.
type Result struct {
	// Decision is allow or suppress.
	Decision Decision `json:"decision"`

	// Reason explains the verdict in one or two sentences.
	Reason string `json:"reason"`

	// Subject and Body are the message. They are written by the reader, not
	// rendered from a template, so nothing in them is asserted by the
	// pipeline.
	Subject string `json:"subject"`
	Body    string `json:"body"`

	// Claims are the assertions the message makes, with their evidence.
	Claims []Claim `json:"claims"`

	// Unverified is true when the reader could not be reached and the
	// configured policy allowed the pipeline's own message to be delivered
	// instead. Such a message is not verified, and the record says so.
	Unverified bool `json:"unverified,omitempty"`

	// Model names the reader that produced the verdict.
	Model string `json:"model,omitempty"`
}

// Allowed reports whether the alert may be delivered.
func (r Result) Allowed() bool { return r.Decision == DecisionAllow }

// Request is the question the verifier is asked to answer.
type Request struct {
	// Program is the program as it was observed in this scan. Its raw fields
	// and page markers are the evidence.
	Program domain.Program

	// Changes are the changes the pipeline claims to have observed.
	Changes domain.ChangeSet

	// Decision is the eligibility decision, with its reasons.
	Decision domain.EligibilityDecision

	// Fresh carries the observation intervals that bound the change.
	Fresh domain.Freshness

	// Now is the time the observation was made.
	Now time.Time
}

// Verifier judges one candidate alert.
type Verifier interface {
	// Verify returns the verdict for the request.
	Verify(ctx context.Context, req Request) (Result, error)

	// Name identifies the verifier in logs and records.
	Name() string
}
