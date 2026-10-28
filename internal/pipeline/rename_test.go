package pipeline_test

import (
	"strings"
	"testing"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/state"
)

// A program the platform renamed must not be reported as a disappearance plus
// a false birth. The redirect is the platform's own statement that the two
// slugs are one program, and the record is corrected to say so.
func TestProgramRenameCarriesHistoryOver(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	// The platform now lists the program under a new slug and redirects the
	// old address to it.
	src.mu.Lock()
	src.refs = append(src.refs, domain.ProgramRef{
		Source: "fake", ID: "beta", Slug: "beta", Name: "Program beta (ex-alpha)",
		URL:     "https://fake.test/programs/beta",
		Listing: domain.Listing{Status: "LIVE", State: "published", RewardRaw: "$5,000"},
	})
	src.records["beta"] = defaultRecord("beta")
	src.redirects = map[string]string{"alpha": "beta"}
	src.mu.Unlock()
	dropRef(t, src, "alpha")

	_, err := runScanner(t, src, dir)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := state.NewFileStore(dir).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// The old identity is closed, so the coverage guard stops flagging it.
	old, held := snap.Program("fake:alpha")
	if !held {
		t.Fatal("the renamed program was dropped from state without a record")
	}
	if old.State != domain.StateEnded {
		t.Errorf("old identity state = %q, want ended", old.State)
	}

	// The surviving identity carries the rename in its history, citing the
	// redirect: this is the evidence, not a name-similarity guess.
	store := state.NewFileStore(dir)
	entries, err := store.HistoryFor(t.Context(), "fake:beta")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		for _, k := range e.Kinds {
			if k == string(domain.ChangeProgramRenamed) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("the surviving identity has no PROGRAM_RENAMED entry; entries = %d", len(entries))
	}
}

// Without a redirect answer, a vanished program is still a disappearance: the
// degraded report is the only honest record of a program the sweep cannot see.
func TestVanishedProgramWithoutRedirectStaysAbsent(t *testing.T) {
	src := newFakeSource("alpha")
	dir := t.TempDir()
	if _, err := runScanner(t, src, dir); err != nil {
		t.Fatal(err)
	}

	// alpha is gone and its address answers nothing. beta is unrelated.
	src.mu.Lock()
	src.refs = append(src.refs, domain.ProgramRef{
		Source: "fake", ID: "beta", Slug: "beta", Name: "Program beta",
		URL:     "https://fake.test/programs/beta",
		Listing: domain.Listing{Status: "LIVE", State: "published", RewardRaw: "$5,000"},
	})
	src.records["beta"] = defaultRecord("beta")
	src.redirects = map[string]string{}
	src.mu.Unlock()
	dropRef(t, src, "alpha")

	_, err := runScanner(t, src, dir)
	if err == nil {
		t.Fatal("a program that vanished without a redirect did not degrade the scan")
	}
	if !strings.Contains(err.Error(), "degraded") {
		t.Errorf("error = %v, want the degraded report", err)
	}

	snap, err := state.NewFileStore(dir).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if old, held := snap.Program("fake:alpha"); held && old.State == domain.StateEnded {
		t.Error("the old identity was closed without any evidence it moved")
	}
}

// dropRef removes a program from the listing the fake source publishes.
func dropRef(t *testing.T, src *fakeSource, id string) {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	kept := src.refs[:0]
	for _, r := range src.refs {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	src.refs = kept
}
