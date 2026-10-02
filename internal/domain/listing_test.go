package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

func refWithListing(l domain.Listing) domain.ProgramRef {
	return domain.ProgramRef{Source: "test", ID: "p", Slug: "p", Listing: l}
}

func programWithSignal(s domain.ListingSignal) domain.Program {
	return domain.Program{ID: "test:p", Source: "test", Slug: "p", Listing: s}
}

func signalFrom(l domain.Listing) domain.ListingSignal {
	return domain.ListingSignal{
		UpdatedAt:            l.UpdatedAt,
		Status:               l.Status,
		State:                l.State,
		RewardRaw:            l.RewardRaw,
		RewardsPaidRaw:       l.RewardsPaidRaw,
		ActivityStatus:       l.ActivityStatus,
		Unending:             l.Unending,
		Categories:           l.Categories,
		ProjectTypes:         l.ProjectTypes,
		Technologies:         l.Technologies,
		SubmissionCountKnown: l.SubmittedReportsKnown,
	}
}

// TestListingChangedSinceIsNotInverted is a regression test.
//
// The original implementation negated the comparison, so an unchanged program
// always reported a change. Every program therefore re-fetched its detail page
// on every five-minute scan, which defeated the entire two-tier design and made
// a scan take minutes instead of seconds. A sign error here is invisible in
// output and expensive in practice, so it is pinned explicitly.
func TestListingChangedSinceIsNotInverted(t *testing.T) {
	base := domain.Listing{
		UpdatedAt:      timePtr(t, "2026-09-28T00:00:00Z"),
		Status:         "LIVE",
		State:          "published",
		RewardRaw:      "$20,000",
		ActivityStatus: "Active",
		Unending:       true,
		Categories:     []string{"Web", "apps"},
		ProjectTypes:   []string{"CEX"},
	}

	p := programWithSignal(signalFrom(base))

	if p.ListingChangedSince(refWithListing(base)) {
		t.Error("an identical listing was reported as changed")
	}
	if !p.ListingChangedSince(refWithListing(base)) == false {
		t.Error("ListingChangedSince returned true for an unchanged listing")
	}
}

// TestListingTriggerIgnoresVolatileFields verifies that fields which change on
// every observation do not trigger an expensive read.
func TestListingTriggerIgnoresVolatileFields(t *testing.T) {
	base := domain.Listing{
		UpdatedAt:      timePtr(t, "2026-09-28T00:00:00Z"),
		Status:         "LIVE",
		State:          "published",
		RewardRaw:      "$20,000",
		ActivityStatus: "Active",
		Categories:     []string{"Web"},
		ProjectTypes:   []string{"CEX"},
	}
	p := programWithSignal(signalFrom(base))

	t.Run("submission count does not trigger", func(t *testing.T) {
		grown := base
		n := 99
		grown.SubmittedReports = &n
		grown.SubmittedReportsKnown = true
		if p.ListingChangedSince(refWithListing(grown)) {
			t.Error("a rising submission count triggered a detail read")
		}
		if !grown.SubmissionsChanged(base) {
			t.Error("the submission change was not observable")
		}
	})

	t.Run("render counter does not trigger", func(t *testing.T) {
		// The source increments this on every page render, so treating it as a
		// change would mark most programs changed on every scan.
		bumped := base
		bumped.RenderCounter = base.RenderCounter + 7
		if p.ListingChangedSince(refWithListing(bumped)) {
			t.Error("a render counter increment triggered a detail read")
		}
	})

	t.Run("render counter is not persisted", func(t *testing.T) {
		// It changes on every render, so writing it into version-controlled
		// state would produce a diff on every run for no benefit. The check is
		// made against the serialized form, which is what actually reaches disk.
		encoded, err := json.Marshal(signalFrom(domain.Listing{
			RenderCounter: 999,
			Status:        "LIVE",
		}))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(encoded), "render") {
			t.Errorf("persisted state still carries the render counter: %s", encoded)
		}
	})

	t.Run("bounty change triggers", func(t *testing.T) {
		raised := base
		raised.RewardRaw = "$50,000"
		if !p.ListingChangedSince(refWithListing(raised)) {
			t.Error("a raised bounty did not trigger a detail read")
		}
	})

	t.Run("state change triggers", func(t *testing.T) {
		ended := base
		ended.Status = "ENDED"
		if !p.ListingChangedSince(refWithListing(ended)) {
			t.Error("a state change did not trigger a detail read")
		}
	})

	t.Run("update marker change triggers", func(t *testing.T) {
		moved := base
		moved.UpdatedAt = timePtr(t, "2026-10-01T00:00:00Z")
		if !p.ListingChangedSince(refWithListing(moved)) {
			t.Error("an updated marker did not trigger a detail read")
		}
	})

	t.Run("classification change triggers", func(t *testing.T) {
		reclassified := base
		reclassified.ProjectTypes = []string{"DeFi"}
		if !p.ListingChangedSince(refWithListing(reclassified)) {
			t.Error("a classification change did not trigger a detail read")
		}
	})
}

// TestListingSignalRoundTripIsSymmetric verifies that a signal projected back to
// a Listing compares equal to the Listing it came from.
//
// An asymmetric projection is how the trigger comparison silently starts
// reporting every program as changed.
func TestListingSignalRoundTripIsSymmetric(t *testing.T) {
	submissions := 42
	original := domain.Listing{
		UpdatedAt:             timePtr(t, "2026-09-28T00:00:00Z"),
		RenderCounter:         1234,
		Status:                "LIVE",
		State:                 "published",
		RewardRaw:             "$20,000",
		RewardsPaidRaw:        "$8,000",
		ActivityStatus:        "Active",
		Unending:              true,
		Categories:            []string{"Web"},
		ProjectTypes:          []string{"CEX"},
		Technologies:          []string{"Solidity"},
		SubmittedReportsKnown: true,
		SubmittedReports:      &submissions,
	}
	s := domain.ListingSignal{
		UpdatedAt:            original.UpdatedAt,
		Status:               original.Status,
		State:                original.State,
		RewardRaw:            original.RewardRaw,
		RewardsPaidRaw:       original.RewardsPaidRaw,
		ActivityStatus:       original.ActivityStatus,
		Unending:             original.Unending,
		Categories:           original.Categories,
		ProjectTypes:         original.ProjectTypes,
		Technologies:         original.Technologies,
		SubmissionCountKnown: original.SubmittedReportsKnown,
		SubmissionCount:      42,
	}
	restored := s.AsListing()

	if !restored.Equal(original) {
		t.Error("a signal did not round-trip to an equal listing")
	}
	if !original.Equal(restored) {
		t.Error("equality is not symmetric")
	}
	if original.ChangedSince(restored) {
		t.Error("an unchanged round-trip reported a change")
	}
}

// TestListingEqualTreatsNilAndEmptyAlike verifies that an absent label list and
// an empty one are the same observation.
func TestListingEqualTreatsNilAndEmptyAlike(t *testing.T) {
	withNil := domain.Listing{Status: "LIVE"}
	withEmpty := domain.Listing{Status: "LIVE", Categories: []string{}}
	if !withNil.Equal(withEmpty) {
		t.Error("nil and empty label lists compared as different")
	}
	if withNil.ChangedSince(withEmpty) {
		t.Error("nil and empty label lists reported a change")
	}
}

func timePtr(t *testing.T, v string) *time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatalf("parse %q: %v", v, err)
	}
	return &parsed
}
