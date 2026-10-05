package diff_test

import (
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/diff"
	"github.com/eadeshina/hunter/internal/domain"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func base(id string) domain.Program {
	p := domain.Program{
		ID: "fake:" + id, Source: "fake", Slug: id, Name: "Program " + id,
		State:      domain.StateLive,
		Targets:    domain.Targets{{Kind: domain.KindWeb, Identifier: "*." + id + ".example.com", InScope: true}},
		KYC:        domain.TriNo,
		POC:        domain.TriYes,
		Fee:        domain.FeeGate{Present: domain.TriNo},
		Reputation: domain.ReputationGate{Present: domain.TriNo},
	}
	p.Finalize()
	return p
}

func compare(prev, cur domain.Program) domain.Diff {
	return diff.NewDetector(func() time.Time { return at }).Compare(prev, cur)
}

func mustKind(t *testing.T, cs domain.ChangeSet, kind domain.ChangeKind) domain.Change {
	t.Helper()
	for _, c := range cs {
		if c.Kind == kind {
			return c
		}
	}
	t.Fatalf("expected a %s change, got %v", kind, cs.Kinds())
	return domain.Change{}
}

func mustNotHave(t *testing.T, cs domain.ChangeSet, kind domain.ChangeKind) {
	t.Helper()
	for _, c := range cs {
		if c.Kind == kind {
			t.Fatalf("did not expect a %s change, got %v", kind, cs.Kinds())
		}
	}
}

// A lowered requirement opens the program; a raised one closes it. Both must be
// distinguishable from the undirected summary alone.
func TestReputationDirectionIsRecorded(t *testing.T) {
	prev := base("a")
	prev.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 100}
	prev.Finalize()

	cur := prev
	cur.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 50}
	cur.Finalize()

	d := compare(prev, cur)

	lowered := mustKind(t, d.Changes, domain.ChangeReputationLowered)
	if !lowered.Improved() {
		t.Fatal("a lowered reputation requirement must be recorded as an improvement")
	}
	if !lowered.Alertable() {
		t.Fatal("a lowered reputation requirement must be capable of alerting")
	}
	if lowered.Before != "100 reputation points" || lowered.After != "50 reputation points" {
		t.Fatalf("delta text = %q -> %q, want the two observed points",
			lowered.Before, lowered.After)
	}

	// The reverse movement is the opposite event.
	raised := mustKind(t, compare(cur, prev).Changes, domain.ChangeReputationRaised)
	if !raised.Degraded() {
		t.Fatal("a raised reputation requirement must be recorded as a degradation")
	}
	if raised.Alertable() {
		t.Fatal("a raised requirement must never alert on its own")
	}
}

// The undirected summary is still emitted, so a consumer that only cares that
// something moved does not have to know about direction at all.
func TestUndirectedSummaryIsStillEmitted(t *testing.T) {
	prev := base("a")
	prev.Fee = domain.FeeGate{Present: domain.TriYes, USD: 10}
	prev.Finalize()
	cur := prev
	cur.Fee = domain.FeeGate{Present: domain.TriYes, USD: 0}
	cur.Finalize()

	d := compare(prev, cur)
	mustKind(t, d.Changes, domain.ChangeFeeChanged)
	mustKind(t, d.Changes, domain.ChangeFeeRemoved)
	mustNotHave(t, d.Changes, domain.ChangeFeeIncreased)
}

// KYC removal opens access; KYC introduction closes it. A gate that merely
// becomes unreadable has no direction, because a parser regression must never
// raise an "access opened" alert.
func TestKYCDirectionRequiresBothSidesKnown(t *testing.T) {
	prev := base("a")
	prev.KYC = domain.TriYes
	prev.Finalize()

	cur := prev
	cur.KYC = domain.TriNo
	cur.Finalize()
	removed := mustKind(t, compare(prev, cur).Changes, domain.ChangeKYCRemoved)
	if !removed.Improved() || !removed.Alertable() {
		t.Fatal("removing a KYC requirement must be an alertable improvement")
	}

	intro := mustKind(t, compare(cur, prev).Changes, domain.ChangeKYCRequired)
	if intro.Alertable() {
		t.Fatal("introducing a KYC requirement must not alert")
	}

	// Previously known, now unreadable: recorded, but with no direction.
	faded := prev
	faded.KYC = domain.TriUnknown
	faded.Finalize()
	d := compare(prev, faded)
	mustKind(t, d.Changes, domain.ChangeKYCChanged)
	mustNotHave(t, d.Changes, domain.ChangeKYCRemoved)
	mustNotHave(t, d.Changes, domain.ChangeKYCRequired)
}

// An asset that keeps its identifier but becomes testable is invisible to an
// in-scope-only comparison. It is the single highest-value scope event and must
// not be dropped.
func TestAssetMovedInScopeIsDetected(t *testing.T) {
	prev := base("a")
	prev.Targets = domain.Targets{{
		Kind: domain.KindAPI, Identifier: "https://api.a.example.com", InScope: false,
	}}
	prev.Finalize()

	cur := prev
	cur.Targets = domain.Targets{{
		Kind: domain.KindAPI, Identifier: "https://api.a.example.com", InScope: true,
	}}
	cur.Finalize()

	d := compare(prev, cur)
	moved := mustKind(t, d.Changes, domain.ChangeTargetInScope)
	if !moved.Improved() || !moved.Alertable() {
		t.Fatal("an asset becoming testable must be an alertable improvement")
	}
	if len(moved.Assets) != 1 || moved.Assets[0] != "https://api.a.example.com" {
		t.Fatalf("assets = %v, want the one identifier", moved.Assets)
	}
}

func TestAssetMovedOutOfScopeIsRecordedNotAlerted(t *testing.T) {
	prev := base("a")
	prev.Targets = domain.Targets{{
		Kind: domain.KindAPI, Identifier: "https://api.a.example.com", InScope: true,
	}}
	prev.Finalize()
	cur := prev
	cur.Targets = domain.Targets{{
		Kind: domain.KindAPI, Identifier: "https://api.a.example.com", InScope: false,
	}}
	cur.Finalize()

	moved := mustKind(t, compare(prev, cur).Changes, domain.ChangeTargetOutOfScope)
	if moved.Alertable() {
		t.Fatal("losing testability must never alert on its own")
	}
	if !moved.Degraded() {
		t.Fatal("losing testability must be recorded as a degradation")
	}
}

// Surface direction survives a relabelling: the same hostname, newly described
// as an API, is a change in what can be tested.
func TestSurfaceDirectionFollowsTheProfileVocabulary(t *testing.T) {
	prev := base("a")
	prev.SurfaceTags = domain.NewTags("web_application", "web2")
	prev.Finalize()

	cur := prev
	cur.SurfaceTags = domain.NewTags("web_application", "web2", "api")
	cur.Finalize()

	changed := mustKind(t, compare(prev, cur).Changes, domain.ChangeSurfaceChanged)
	if !changed.Improved() {
		t.Fatal("gaining a surface must be recorded as an improvement")
	}

	lost := mustKind(t, compare(cur, prev).Changes, domain.ChangeSurfaceChanged)
	if !lost.Degraded() {
		t.Fatal("losing a surface must be recorded as a degradation")
	}
}

// Deltas are total: every change yields exactly one delta, and the set is
// order-independent so that window identity cannot depend on map iteration.
func TestDeltasAreTotalAndOrderIndependent(t *testing.T) {
	prev := base("a")
	prev.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 100}
	prev.KYC = domain.TriYes
	prev.Finalize()

	cur := base("a")
	cur.Reputation = domain.ReputationGate{Present: domain.TriYes, Points: 20}
	cur.KYC = domain.TriNo
	cur.Targets = append(append(domain.Targets{}, cur.Targets...),
		domain.Target{Kind: domain.KindAPI, Identifier: "https://api.a.example.com", InScope: true})
	cur.Finalize()

	d := compare(prev, cur)
	ds := d.Changes.Deltas()

	if len(ds) != len(d.Changes) {
		t.Fatalf("got %d deltas for %d changes; the projection must be total", len(ds), len(d.Changes))
	}
	for _, x := range ds {
		if x.Direction == "" {
			t.Fatalf("delta %+v has no direction", x)
		}
	}
	if got := ds.Identity(); got != domain.Deltas(append([]domain.Delta(nil), ds...)).Identity() {
		t.Fatal("identity must be stable")
	}
	reversed := make(domain.Deltas, len(ds))
	for i := range ds {
		reversed[len(ds)-1-i] = ds[i]
	}
	if reversed.Identity() != ds.Identity() {
		t.Fatal("identity must not depend on the order deltas were detected in")
	}
	if len(ds.Improved()) == 0 {
		t.Fatal("the comparison improved access and must record improved deltas")
	}
}

// Losing surface is recorded and never alerts. This is the guarantee that keeps
// the existing-program channel from becoming a firehose of closures.
func TestEveryDegradedKindIsRecordOnly(t *testing.T) {
	for _, k := range []domain.ChangeKind{
		domain.ChangeTargetRemoved, domain.ChangeAPIRemoved,
		domain.ChangeRepositoryRemoved, domain.ChangeMobileRemoved,
		domain.ChangeTargetOutOfScope, domain.ChangeReputationRaised,
		domain.ChangeKYCRequired, domain.ChangeFeeIncreased, domain.ChangeFeeIntroduced,
		domain.ChangePOCRequired, domain.ChangeBountyLowered,
		domain.ChangeProgramPaused, domain.ChangeProgramEnded,
		domain.ChangeSubmissionsChanged, domain.ChangeFirstSeen,
		domain.ChangeMetadataChanged, domain.ChangeRequirementChanged,
		domain.ChangeReputationChanged, domain.ChangeFeeChanged, domain.ChangeKYCChanged,
		domain.ChangePOCChanged, domain.ChangeBountyChanged, domain.ChangeStateChanged,
	} {
		if (domain.Change{Kind: k}).Alertable() {
			t.Errorf("%s must never alert on its own", k)
		}
	}
}

// A submission-count movement must never alert, in either direction.
func TestSubmissionMovementNeverAlerts(t *testing.T) {
	c := domain.Change{Kind: domain.ChangeSubmissionsChanged}
	if c.Alertable() {
		t.Fatal("a moving submission count must never alert")
	}
}

// Every direction-capable kind must be classified one way or the other, so a new
// kind cannot silently be both alertable and record-only by omission.
func TestEveryKindIsClassified(t *testing.T) {
	all := []domain.ChangeKind{
		domain.ChangeTargetAdded, domain.ChangeAPIAdded, domain.ChangeRepositoryAdded,
		domain.ChangeMobileAdded, domain.ChangeTargetInScope, domain.ChangeReputationLowered,
		domain.ChangeKYCRemoved, domain.ChangeFeeReduced, domain.ChangeFeeRemoved,
		domain.ChangePOCRemoved, domain.ChangeBountyRaised, domain.ChangeProgramReactivated,
		domain.ChangeTargetRemoved, domain.ChangeAPIRemoved, domain.ChangeRepositoryRemoved,
		domain.ChangeMobileRemoved, domain.ChangeTargetOutOfScope, domain.ChangeReputationRaised,
		domain.ChangeKYCRequired, domain.ChangeFeeIncreased, domain.ChangeFeeIntroduced,
		domain.ChangePOCRequired, domain.ChangeBountyLowered, domain.ChangeProgramPaused,
		domain.ChangeProgramEnded, domain.ChangeSubmissionsChanged, domain.ChangeFirstSeen,
	}
	for _, k := range all {
		if !k.Classified() {
			t.Errorf("%s is unclassified: neither alertable nor record-only", k)
		}
		if k.Alertable() && k.RecordOnly() {
			t.Errorf("%s is classified on both sides", k)
		}
	}
}
