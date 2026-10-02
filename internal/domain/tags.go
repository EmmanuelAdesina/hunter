package domain

import (
	"sort"
	"strings"
)

// Tags is a sorted, de-duplicated set of classification labels.
//
// Tags are the shared vocabulary between classification, policy, scoring, and
// the human-readable explanation attached to every decision. They are stored as
// sorted slices rather than maps so that serialized state is stable and diffs
// stay readable.
type Tags []string

// NewTags builds a sorted, de-duplicated tag set from the given values.
// Empty and whitespace-only values are discarded; casing and surrounding
// whitespace are normalized so that "Web", " web ", and "WEB" collapse together.
func NewTags(values ...string) Tags {
	if len(values) == 0 {
		return Tags{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make(Tags, 0, len(values))
	for _, v := range values {
		t := NormalizeTag(v)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// NormalizeTag lowercases and trims a single tag value.
func NormalizeTag(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// Has reports whether the set contains tag.
func (t Tags) Has(tag string) bool {
	needle := NormalizeTag(tag)
	for _, v := range t {
		if v == needle {
			return true
		}
	}
	return false
}

// HasAny reports whether the set contains at least one of the given tags.
func (t Tags) HasAny(tags ...string) bool {
	for _, tag := range tags {
		if t.Has(tag) {
			return true
		}
	}
	return false
}

// HasAll reports whether the set contains every one of the given tags.
func (t Tags) HasAll(tags ...string) bool {
	for _, tag := range tags {
		if !t.Has(tag) {
			return false
		}
	}
	return true
}

// Intersect returns the sorted intersection of t and other.
func (t Tags) Intersect(other Tags) Tags {
	if len(t) == 0 || len(other) == 0 {
		return Tags{}
	}
	out := make(Tags, 0)
	for _, v := range t {
		if other.Has(v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Subtract returns the sorted members of t that are absent from other.
func (t Tags) Subtract(other Tags) Tags {
	if len(t) == 0 {
		return Tags{}
	}
	out := make(Tags, 0)
	for _, v := range t {
		if !other.Has(v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Except returns members of t absent from other, or all of t when only is set.
func (t Tags) Except(other Tags, only bool) Tags {
	if !only {
		return t.Clone()
	}
	return t.Subtract(other)
}

// Clone returns an independent copy, so callers cannot mutate shared state.
func (t Tags) Clone() Tags {
	if t == nil {
		return nil
	}
	out := make(Tags, len(t))
	copy(out, t)
	return out
}

// Add returns a new sorted set with the given values inserted.
func (t Tags) Add(values ...string) Tags { return NewTags(append(t.Clone(), values...)...) }

// With returns a new sorted set with values added and removed.
func (t Tags) With(add []string, remove []string) Tags {
	merged := NewTags(append(t.Clone(), add...)...)
	return merged.Subtract(NewTags(remove...))
}

// Join renders the set for inclusion in an explanation sentence.
func (t Tags) Join() string { return strings.Join(t, ", ") }

func (t Tags) String() string { return t.Join() }

// sortedUniqueStrings returns the input with duplicates removed and the order
// normalized, preserving each value's original text.
func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Equal reports whether two sets contain exactly the same members.
func (t Tags) Equal(other Tags) bool {
	if len(t) != len(other) {
		return false
	}
	for i := range t {
		if t[i] != other[i] {
			return false
		}
	}
	return true
}
