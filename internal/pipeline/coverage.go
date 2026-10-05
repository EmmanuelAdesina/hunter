package pipeline

import (
	"sort"

	"github.com/eadeshina/hunter/internal/domain"
	"github.com/eadeshina/hunter/internal/state"
)

// CoverageReport is the outcome of comparing what the system knew against what
// the sweep saw.
type CoverageReport struct {
	// Expected is how many previously-known programs the sweep had an obligation
	// to observe. Terminal programs are excluded: a program the platform said was
	// finished, or unlisted, is allowed to disappear.
	Expected int

	// Observed is how many of those the sweep actually saw.
	Observed int

	// Missing is Expected minus Observed. It counts programs inside the grace
	// period as well as those beyond it.
	Missing int

	// Absent names programs missing beyond the grace period.
	Absent []string

	// Departed names programs removed from state because they are gone and the
	// system had already recorded them as finished.
	Departed []string

	// Ratio is Observed over Expected, or -1 when there was nothing to expect.
	Ratio float64
}

// MissingReport returns the program names worth showing a human, absent first.
func (r CoverageReport) MissingReport() []string {
	return append(append([]string{}, r.Absent...), r.Departed...)
}

// applyCoverage accounts for programs the sweep did not see, advances the absence
// counter on each, and removes the ones the platform has finished with.
//
// # Why this runs against the discovery set and not the evaluated set
//
// A program can be discovered and still fail to evaluate, which is an error path
// already counted by Attempted and Evaluated. What this answers is the narrower
// and more dangerous question: did the sweep ever hear about this program at all?
//
// A program that vanished from the listing is invisible to every other check in
// the system. A comparison against a program that is not observed produces no
// change, and no change produces no evidence of anything - so a scope expansion on
// a program discovery has quietly dropped would produce exactly the same output
// as a quiet platform. That equivalence is the failure this exists to break.
//
// # Why expectedIDs is passed in rather than read from the snapshot
//
// By the time this runs, the snapshot holds the union of previously-known
// programs and programs discovered this sweep. Reading the denominator from it
// would count brand-new programs as observed, inflating the ratio precisely when
// coverage is worst. The obligation is set by what was known at load time, so
// that set is captured then and carried here.
//
// # Why absence is counted rather than acted on immediately
//
// One missed sweep is a network event - a dropped page, a rate limit, a
// deployment. Treating it as a fact would make the monitor cry wolf on every
// transient. The counter is what separates the two, and it saturates so that a
// permanently departed program stops rewriting state on every run.
func applyCoverage(snap *state.Snapshot, expectedIDs []string, seen map[string]struct{}, grace int, evict bool) CoverageReport {
	if grace <= 0 {
		grace = 1
	}
	// The counter is allowed to run one step past the point where absence is
	// reported, then stops. That final step is what distinguishes "reported as
	// absent" from "counting continues", and stopping there is what keeps a
	// permanently unobserved program from rewriting state on every sweep.
	cap := grace + 1

	rep := CoverageReport{Ratio: -1}

	// Identifier order, so eviction and the reported lists are deterministic
	// rather than dependent on map iteration.
	ids := append([]string(nil), expectedIDs...)
	sort.Strings(ids)

	for _, id := range ids {
		p, held := snap.Program(id)

		if _, ok := seen[id]; ok {
			if !held {
				// Seen this sweep but no longer held: nothing to reconcile.
				rep.Observed++
				continue
			}
			if p.AbsentScans != 0 {
				// The program is back. Clearing the counter here rather than on
				// some later evaluation is what makes a recovered sweep return the
				// program to full trust immediately.
				p.AbsentScans = 0
				snap.Programs[id] = p
			}
			rep.Observed++
			continue
		}

		rep.Missing++

		if !held {
			// It was expected and is no longer held at all. That should not happen,
			// because eviction only happens here, but counting it as missing is the
			// safe reading.
			continue
		}

		if p.Terminal() {
			// The program said it was finished, or the platform unlisted it. Its
			// absence is a departure, not a coverage failure.
			if evict && p.AbsentScans >= cap {
				delete(snap.Programs, id)
				rep.Departed = append(rep.Departed, displayProgramName(p))
				rep.Missing--
				continue
			}
			p.AbsentScans = saturate(p.AbsentScans+1, cap)
			snap.Programs[id] = p
			continue
		}

		// Still accepting reports, and no longer published. Either the platform
		// dropped it or discovery stopped reaching it; both make every future
		// change to it undetectable.
		p.AbsentScans = saturate(p.AbsentScans+1, cap)
		snap.Programs[id] = p
		// Reported once the absence has survived the full grace period. Beyond
		// this point it keeps being reported every sweep, because a program that
		// has been invisible for a week is not a transient and must keep saying so
		// until it is either seen again or evicted.
		if p.AbsentScans >= grace {
			rep.Absent = append(rep.Absent, displayProgramName(p))
		}
	}

	// Expected excludes terminal programs, which were not expected to be
	// published. Observed is counted above for everything seen, so the ratio is
	// measured against the live obligation only.
	rep.Expected = rep.Observed + liveMissing(snap, ids, seen)
	if rep.Expected > 0 {
		rep.Ratio = float64(rep.Observed) / float64(rep.Expected)
	}
	return rep
}

// liveMissing counts non-terminal programs still held that the sweep did not see.
func liveMissing(snap *state.Snapshot, ids []string, seen map[string]struct{}) int {
	n := 0
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		if p, held := snap.Program(id); held && !p.Terminal() {
			n++
		}
	}
	return n
}

// saturate caps a counter so a settled condition stops changing state.
func saturate(v, cap int) int {
	if cap <= 0 {
		cap = 1
	}
	if v > cap {
		return cap
	}
	return v
}

func displayProgramName(p domain.Program) string {
	if p.Name != "" {
		return p.Name + " (" + p.ID + ")"
	}
	return p.ID
}
