package config

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/domain"
)

// ChangeWindowsConfig sizes the recency window of each class of change.
//
// The launch window answers "is this program new?". These answer a different
// question: "is this change recent?". A program can be five years old and have
// had its API scope extended nine minutes ago, and conflating the two ages is
// what previously made such a change unreportable.
//
// Resolution is a three-step fallback so that a profile can be as coarse or as
// precise as it wants without a field per event kind:
//
//	per-kind key  ->  class key  ->  default
//
// A missing key at any level falls through to the next, and an unconfigured
// class falls through to the default. There is deliberately no way to express
// "no window": a change trigger with no window would fire forever, so absence
// resolves to the default rather than to infinity.
type ChangeWindowsConfig struct {
	// Default applies to every change with no more specific window. It is
	// required: without it an unconfigured trigger would be un-gated.
	Default stringDuration `yaml:"default"`

	// Class keys size a whole class of related events at once, e.g.
	// "access_improved" or "scope_expansion".
	Class map[string]stringDuration `yaml:",inline"`

	// BundleWindow is how far apart two changes may fall and still be bundled into
	// one opportunity window.
	//
	// Bundling is temporal grouping, not semantic rewriting. Four changes observed
	// across one scan are one window containing four atomic deltas, not four alerts
	// and not one fused claim. Zero gives one window per scan.
	BundleWindow stringDuration `yaml:"bundle_window"`

	// MaxAge is how old a window may be before it is reported as expired. It
	// defaults to the widest configured change window, because a window older than
	// the longest window its triggers could ever satisfy is stale by definition.
	MaxAge stringDuration `yaml:"max_age"`

	// MaxPostChangeSubmissions is how many submissions may accumulate after a
	// window opened before it is treated as crowded.
	//
	// It is a measured threshold rather than a deadline, and zero disables it. The
	// count is the platform's own published figure; a decrease never crowds a
	// window.
	MaxPostChangeSubmissions int `yaml:"max_post_change_submissions"`

	// windows is the resolved lookup built during validation.
	windows map[string]time.Duration
}

// BundleWindowDuration returns how far apart two changes may fall and still be
// bundled.
func (c ChangeWindowsConfig) BundleWindowDuration() time.Duration {
	return time.Duration(c.BundleWindow)
}

// WidestWindow returns the largest configured window, used as the default expiry.
func (c ChangeWindowsConfig) WidestWindow() time.Duration {
	widest := time.Duration(c.Default)
	for _, v := range c.windows {
		if v > widest {
			widest = v
		}
	}
	return widest
}

// changeWindowClasses maps a change kind onto its configuration class.
//
// The classes are semantic rather than per-kind so that adding a new change kind
// cannot silently end up with no window: an unclassified kind falls through to
// the default, and this test fails if one is added without a decision.
var changeWindowClasses = map[domain.ChangeKind]string{
	// New surface, more to test.
	domain.ChangeTargetAdded:        "scope_expansion",
	domain.ChangeAPIAdded:           "scope_expansion",
	domain.ChangeRepositoryAdded:    "scope_expansion",
	domain.ChangeMobileAdded:        "scope_expansion",
	domain.ChangeTargetInScope:      "scope_expansion",
	domain.ChangeScopeChanged:       "scope_expansion",
	domain.ChangeSurfaceChanged:     "scope_expansion",
	domain.ChangeScopeReviewChanged: "scope_expansion",
	domain.ChangeCryptoReclassified: "scope_expansion",

	// The program became reachable, or better compensated.
	domain.ChangeReputationLowered: "access_improved",
	domain.ChangeKYCRemoved:        "access_improved",
	domain.ChangeFeeReduced:        "access_improved",
	domain.ChangeFeeRemoved:        "access_improved",
	domain.ChangePOCRemoved:        "access_improved",
	domain.ChangeBountyRaised:      "access_improved",

	// A program came back to life.
	domain.ChangeProgramReactivated: "reactivated",
}

// AllChangeWindowClasses returns every class name, for validation messages.
func AllChangeWindowClasses() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(changeWindowClasses))
	for _, c := range changeWindowClasses {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ChangeWindowFor returns the window governing a change kind.
//
// The three-step fallback is applied here rather than at validation time so that
// a kind added after the profile was loaded still resolves.
func (c ChangeWindowsConfig) ChangeWindowFor(kind domain.ChangeKind) time.Duration {
	key := string(kind)
	if v, ok := c.windows[key]; ok {
		return v
	}
	if class, ok := changeWindowClasses[kind]; ok {
		if v, ok := c.windows[class]; ok {
			return v
		}
	}
	return time.Duration(c.Default)
}

// ClassOf returns the configuration class for a kind, and whether one exists.
func ClassOf(kind domain.ChangeKind) (string, bool) {
	c, ok := changeWindowClasses[kind]
	return c, ok
}

// resolve builds the lookup table during validation.
func (c *ChangeWindowsConfig) resolve(errs *[]string) {
	resolved := make(map[string]time.Duration, len(c.Class)+1)

	if c.Default <= 0 {
		// A missing default would leave every unconfigured trigger un-gated, which
		// is the firehose this system exists to avoid. It is a hard error rather
		// than a silent default so that the profile author has to be explicit.
		*errs = append(*errs,
			"notifications.change_windows.default must be set: without it a change trigger has no recency window")
	}
	resolved["default"] = time.Duration(c.Default)

	classes := map[string]struct{}{"default": {}}
	for _, name := range AllChangeWindowClasses() {
		classes[name] = struct{}{}
	}

	for key, v := range c.Class {
		name := strings.ToLower(strings.TrimSpace(key))
		if name == "" {
			continue
		}
		if name != "default" {
			if _, known := classes[name]; !known {
				*errs = append(*errs, fmt.Sprintf(
					"notifications.change_windows has unknown key %q: valid keys are default, %s, or any change kind in snake_case",
					key, strings.Join(AllChangeWindowClasses(), ", ")))
				continue
			}
		}
		if v < 0 {
			*errs = append(*errs, fmt.Sprintf("notifications.change_windows.%s must be >= 0", name))
			continue
		}
		resolved[name] = time.Duration(v)
	}
	c.windows = resolved
}

// changeWindows returns the configured windows, defaulted.
func (p *Profile) changeWindows() ChangeWindowsConfig {
	w := p.Notifications.ChangeWindows
	if len(w.windows) == 0 {
		w.resolve(nil)
	}
	return w
}

// ChangeWindowFor returns the window governing a change kind.
func (p *Profile) ChangeWindowFor(kind domain.ChangeKind) time.Duration {
	return p.changeWindows().ChangeWindowFor(kind)
}
