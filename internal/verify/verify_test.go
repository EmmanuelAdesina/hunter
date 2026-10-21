package verify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// fakeModel answers with canned replies, in order.
type fakeModel struct {
	replies []string
	err     error
	calls   int
	systems []string
	users   []string
}

func (f *fakeModel) Name() string { return "fake" }

func (f *fakeModel) Complete(_ context.Context, system, user string) (string, error) {
	f.calls++
	f.systems = append(f.systems, system)
	f.users = append(f.users, user)
	if f.err != nil {
		return "", f.err
	}
	if len(f.replies) == 0 {
		return "", errors.New("no reply configured")
	}
	reply := f.replies[0]
	if len(f.replies) > 1 {
		f.replies = f.replies[1:]
	}
	return reply, nil
}

func testRequest() Request {
	max := 10000.0
	return Request{
		Program: domain.Program{
			ID:             "hackenproof:coinex-web-and-mobile",
			Name:           "CoinEx Web & Mobile",
			URL:            "https://hackenproof.com/programs/coinex-web-and-mobile",
			Source:         "hackenproof",
			State:          domain.StateEnded,
			RawStatus:      "LIVE",
			RawState:       "published",
			ActivityStatus: "Completed",
			PageMarkers:    map[string]string{"liveness_badge": "Ended", "program_left": "2 days ago"},
			MaxBountyUSD:   &max,
			Reputation:     domain.ReputationGate{Present: domain.TriNo},
			Fee:            domain.FeeGate{Present: domain.TriNo},
			KYC:            domain.TriNo,
			POC:            domain.TriNo,
		},
		Changes: domain.ChangeSet{{
			Kind:      domain.ChangeProgramReactivated,
			Severity:  domain.SeverityHigh,
			Direction: domain.DirectionImproved,
			Field:     "state",
			Before:    "paused",
			After:     "live",
		}},
		Decision: domain.EligibilityDecision{Eligible: true, Reasons: []string{"program state is live"}},
		Now:      time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
	}
}

func stageWith(model Model, repair int) *Stage {
	s, err := NewStage(StageConfig{Model: model, RepairAttempts: repair, SubjectPrefix: "[HUNTER] "})
	if err != nil {
		panic(err)
	}
	return s
}

// A reader that contradicts the evidence withholds the alert.
func TestSuppressionWhenTheEvidenceContradictsTheClaim(t *testing.T) {
	model := &fakeModel{replies: []string{`{
		"decision": "suppress",
		"reason": "live.activity_status is Completed and page.liveness_badge is Ended, so the program is not accepting reports",
		"subject": "",
		"body": "",
		"claims": []
	}`}}

	res, err := stageWith(model, 0).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Allowed() {
		t.Fatal("the alert was allowed although the reader suppressed it")
	}
	if !strings.Contains(res.Reason, "Completed") {
		t.Errorf("reason = %q, want it to name the contradicting fact", res.Reason)
	}
}

// A reader that supports the change produces the message, and the subject
// prefix is applied.
func TestAllowanceKeepsTheReadersMessage(t *testing.T) {
	model := &fakeModel{replies: []string{`{
		"decision": "allow",
		"reason": "the page shows the program is open and the bounty was raised",
		"subject": "CoinEx raised its bounty ceiling to $10,000",
		"body": "CoinEx Web & Mobile raised its bounty ceiling to $10,000. The program is live and takes reports with no reputation, KYC, or fee requirement.",
		"claims": [
			{"statement": "the bounty ceiling is $10,000", "verdict": "supported", "evidence": ["gate.bounty_ceiling_usd"]},
			{"statement": "the program is live", "verdict": "supported", "evidence": ["live.activity_status"]}
		]
	}`}}

	res, err := stageWith(model, 0).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Allowed() {
		t.Fatalf("the alert was suppressed: %s", res.Reason)
	}
	if res.Subject != "[HUNTER] CoinEx raised its bounty ceiling to $10,000" {
		t.Errorf("subject = %q", res.Subject)
	}
	if !strings.Contains(res.Body, "$10,000") {
		t.Errorf("body = %q, want the reader's text", res.Body)
	}
}

// A claim that cites a fact the bundle does not contain is not usable. The
// model is asked to correct itself once, and if it does not, the alert is
// withheld.
func TestUnknownEvidenceKeyIsRejected(t *testing.T) {
	model := &fakeModel{replies: []string{`{
		"decision": "allow",
		"reason": "the bounty was raised",
		"subject": "CoinEx raised its bounty",
		"body": "CoinEx raised its bounty.",
		"claims": [
			{"statement": "the bounty was raised", "verdict": "supported", "evidence": ["gate.bounty_ceiling_eur"]}
		]
	}`}}

	res, err := stageWith(model, 0).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Allowed() {
		t.Fatal("the alert was allowed although the claim cited a fact that does not exist")
	}
	if model.calls != 1 {
		t.Errorf("calls = %d, want 1 when no repair is configured", model.calls)
	}
}

// A message that hedges is withheld. A hedge is a claim the reader could not
// support, dressed as caution.
func TestHedgedMessageIsWithheld(t *testing.T) {
	model := &fakeModel{replies: []string{`{
		"decision": "allow",
		"reason": "the program may be open",
		"subject": "CoinEx may be accepting reports again",
		"body": "CoinEx may be accepting reports again, and the bounty possibly increased.",
		"claims": [
			{"statement": "the program is open", "verdict": "supported", "evidence": ["live.activity_status"]}
		]
	}`}}

	res, err := stageWith(model, 0).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Allowed() {
		t.Fatal("a hedged message was delivered")
	}
	if !strings.Contains(res.Reason, "hedges") {
		t.Errorf("reason = %q, want it to name the hedge", res.Reason)
	}
}

// An answer that is not the agreed shape is not used, and the reader is given
// the chance to correct itself.
func TestMalformedAnswerIsCorrectedOnce(t *testing.T) {
	model := &fakeModel{replies: []string{
		"the program reopened, I think",
		`{"decision":"suppress","reason":"live.activity_status is Completed","subject":"","body":"","claims":[]}`,
	}}

	res, err := stageWith(model, 1).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Allowed() {
		t.Fatal("the alert was allowed after a malformed answer")
	}
	if model.calls != 2 {
		t.Errorf("calls = %d, want the reader to be asked twice", model.calls)
	}
	if !strings.Contains(model.users[1], "not the agreed shape") {
		t.Errorf("the repair prompt did not name the problem: %q", model.users[1])
	}
}

// The reader is unreachable. The default is to withhold: an unverified
// notification is the failure this stage exists to prevent.
func TestUnreachableReaderWithholdsByDefault(t *testing.T) {
	model := &fakeModel{err: errors.New("connection refused")}

	res, err := stageWith(model, 0).Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Allowed() {
		t.Fatal("the alert was allowed although the reader could not be reached")
	}
	if !strings.Contains(res.Reason, "could not be verified") {
		t.Errorf("reason = %q, want it to say the alert could not be verified", res.Reason)
	}
}

// An operator can choose the older behavior, and the record says the message
// was not verified.
func TestUnreachableReaderCanFallBackWhenConfigured(t *testing.T) {
	model := &fakeModel{err: errors.New("connection refused")}
	stage, err := NewStage(StageConfig{Model: model, OnUnavailable: "deliver"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := stage.Verify(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Allowed() {
		t.Fatal("the alert was suppressed although the fallback is configured")
	}
	if !res.Unverified {
		t.Error("the fallback result must be marked unverified")
	}
}

// The evidence bundle carries what the reader needs, and the names it uses
// are the names a citation is checked against.
func TestEvidenceCarriesTheObservableFacts(t *testing.T) {
	ev := buildEvidence(testRequest())

	for _, key := range []string{
		"live.status", "live.activity_status", "live.normalized_state",
		"page.liveness_badge", "page.program_left",
		"gate.reputation", "gate.kyc", "gate.poc", "gate.submission_fee",
		"gate.bounty_ceiling_usd",
		"change.kind", "change.before", "change.after",
		"program.name", "program.url",
	} {
		if _, ok := ev.Fact(key); !ok {
			t.Errorf("the bundle is missing %q", key)
		}
	}
	if got := ev.Facts["page.liveness_badge"]; got != "Ended" {
		t.Errorf("page.liveness_badge = %q, want Ended", got)
	}
	if got := ev.Facts["live.activity_status"]; got != "Completed" {
		t.Errorf("live.activity_status = %q, want Completed", got)
	}
}

// The reader is given the instruction that makes the stage worth having, and
// the facts as JSON so that a citation can be checked mechanically.
func TestTheReaderIsInstructedToSuppress(t *testing.T) {
	model := &fakeModel{replies: []string{`{"decision":"suppress","reason":"x","subject":"","body":"","claims":[]}`}}
	stageWith(model, 0).Verify(context.Background(), testRequest())

	if !strings.Contains(model.systems[0], "suppress") {
		t.Error("the instruction does not tell the reader it may withhold the alert")
	}
	if !strings.Contains(model.systems[0], "hedge") {
		t.Error("the instruction does not forbid hedging")
	}
	var bundle map[string]any
	if err := json.Unmarshal([]byte(model.users[0][len("Candidate alert:\n"):]), &bundle); err != nil {
		t.Fatalf("the bundle is not valid JSON: %v", err)
	}
	if _, ok := bundle["facts"]; !ok {
		t.Error("the bundle has no facts")
	}
}
