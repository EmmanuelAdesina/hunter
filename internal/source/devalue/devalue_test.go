package devalue

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"testing"
)

// TestDecodeScalarEncodings pins the encodings that matter most. The -1 index
// in particular must become a present nil, never a zero value: a missing
// reputation requirement decoded as zero would read as "requires no
// reputation", which is a materially different claim.
func TestDecodeScalarEncodings(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    any
	}{
		{"literal string", `["hello"]`, "hello"},
		{"literal bool", `[true]`, true},
		{"null literal", `[null]`, nil},
		{"minus one is absent", `[[-1]]`, []any{nil}},
		{"empty set decodes to an empty list", `[["Set"]]`, []any{}},
		{"nested list", `[[1,2],"a","b"]`, []any{"a", "b"}},
		{"empty list", `[[]]`, []any{}},
		{"object", `[{"k":2},"x","v"]`, map[string]any{"k": "v"}},
		{"reactive wrapper is transparent", `[["Reactive",1],{"k":2},"v"]`, map[string]any{"k": "v"}},
		{"shallow reactive wrapper", `[["ShallowReactive",1],{"k":2},"v"]`, map[string]any{"k": "v"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Decode([]byte(tc.payload), 32)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			got, err := json.Marshal(doc.Root)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			want, err := json.Marshal(tc.want)
			if err != nil {
				t.Fatalf("marshal want: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}

// TestDecodeSpecialNumbers verifies the negative-index sentinels decode to the
// values they stand for, per the encoder's table (-1 undefined, -2 hole, -3
// NaN, -4 and -5 the infinities, -6 negative zero). They appear inside a
// composite, because that is where a reference is valid.
func TestDecodeSpecialNumbers(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		check   func(t *testing.T, v any)
	}{
		{"undefined is absent", `[[-1]]`, func(t *testing.T, v any) {
			if v != nil {
				t.Errorf("got %#v, want nil", v)
			}
		}},
		{"hole is absent", `[[-2]]`, func(t *testing.T, v any) {
			if v != nil {
				t.Errorf("got %#v, want nil", v)
			}
		}},
		{"NaN", `[[-3]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsNaN(f) {
				t.Errorf("got %#v, want NaN", v)
			}
		}},
		{"positive infinity", `[[-4]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsInf(f, 1) {
				t.Errorf("got %#v, want +Inf", v)
			}
		}},
		{"negative infinity", `[[-5]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsInf(f, -1) {
				t.Errorf("got %#v, want -Inf", v)
			}
		}},
		{"negative zero", `[[-6]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || f != 0 || !math.Signbit(f) {
				t.Errorf("got %#v, want -0", v)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Decode([]byte(tc.payload), 16)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			list, ok := AsSlice(doc.Root)
			if !ok || len(list) != 1 {
				t.Fatalf("root = %#v, want one-element list", doc.Root)
			}
			tc.check(t, list[0])
		})
	}
}

// TestDecodeUnknownSentinelsAreErrors verifies that a negative number inside a
// composite that is not one of the encoder's sentinels is a malformed payload,
// reported rather than guessed at. Literal negative values are hoisted as
// entries (TestHoistedNegativeEntriesAreLiterals); inline they are only ever
// sentinels.
func TestDecodeUnknownSentinelsAreErrors(t *testing.T) {
	for _, in := range []string{
		`[[-7]]`,  // SPARSE outside a sparse-array entry
		`[[-8]]`,  // below the sentinel table
		`[[-15]]`, // far below the sentinel table
		`[[-1.5]]`,
		`[[2.5]]`, // a reference must be an integer
	} {
		if _, err := Decode([]byte(in), 16); err == nil {
			t.Errorf("Decode(%q) succeeded, want error", in)
		}
	}
}

// TestHoistedNegativeEntriesAreLiterals pins the mirror image of the sentinel
// table: a negative number stored as an entry of the hoisted array is a
// literal value, not a sentinel. The encoder hoists every value, negative
// ones included, so a page can legitimately carry a field whose value is -3.
func TestHoistedNegativeEntriesAreLiterals(t *testing.T) {
	// Entry 0 is a list referencing entries 2 and 3, which hold the literal
	// numbers -3 and -15.
	doc, err := Decode([]byte(`[[2,3],0,-3,-15]`), 16)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	list, ok := AsSlice(doc.Root)
	if !ok || len(list) != 2 {
		t.Fatalf("root = %#v, want a two-element list", doc.Root)
	}
	if f, ok := list[0].(float64); !ok || f != -3 {
		t.Errorf("first = %#v, want the literal -3", list[0])
	}
	if f, ok := list[1].(float64); !ok || f != -15 {
		t.Errorf("second = %#v, want the literal -15", list[1])
	}
}

// TestSparseArrays verifies the [-7, length, idx, val, ...] encoding decodes
// to a fixed-length list with nil holes, and that malformed variants are
// reported rather than guessed at.
func TestSparseArrays(t *testing.T) {
	t.Run("listed position decodes, holes are nil", func(t *testing.T) {
		// Entry 0 is a sparse array of length 5 holding "x" (entry 1) at
		// index 2.
		doc, err := Decode([]byte(`[[-7,5,2,1],"x"]`), 16)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		list, ok := AsSlice(doc.Root)
		if !ok || len(list) != 5 {
			t.Fatalf("root = %#v, want a five-element list", doc.Root)
		}
		for i, v := range list {
			if i == 2 {
				if s, isStr := v.(string); !isStr || s != "x" {
					t.Errorf("index 2 = %#v, want \"x\"", v)
				}
				continue
			}
			if v != nil {
				t.Errorf("index %d = %#v, want a nil hole", i, v)
			}
		}
	})
	t.Run("all-hole array", func(t *testing.T) {
		doc, err := Decode([]byte(`[[-7,3]]`), 16)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		list, ok := AsSlice(doc.Root)
		if !ok || len(list) != 3 {
			t.Fatalf("root = %#v, want a three-element list", doc.Root)
		}
		for i, v := range list {
			if v != nil {
				t.Errorf("index %d = %#v, want a nil hole", i, v)
			}
		}
	})
	for name, in := range map[string]string{
		"dangling index":     `[[-7,3,1]]`,
		"index beyond len":   `[[-7,3,5,1]]`,
		"negative index":     `[[-7,3,-1,1]]`,
		"non-integer length": `[[-7,2.5]]`,
		"bare sentinel":      `[[-7]]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(in), 16); err == nil {
				t.Errorf("Decode(%q) succeeded, want error", in)
			}
		})
	}
}

// TestEmptyWrapperCollections verifies that a one-element wrapper list, which
// the encoder emits for an empty collection, decodes to an empty list rather
// than to the tag name.
func TestEmptyWrapperCollections(t *testing.T) {
	for _, in := range []string{`[["Set"]]`, `[["Map"]]`} {
		t.Run(in, func(t *testing.T) {
			doc, err := Decode([]byte(in), 16)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			list, ok := AsSlice(doc.Root)
			if !ok || len(list) != 0 {
				t.Errorf("root = %#v, want an empty list", doc.Root)
			}
		})
	}
}

// TestLiteralEntriesAreNotReferences guards the distinction that real data
// depends on. The source stores values such as a scope revision of 8165
// directly in the array; resolving them as indices would corrupt the record.
func TestLiteralEntriesAreNotReferences(t *testing.T) {
	doc, err := Decode([]byte(`[8165,"bitrue"]`), 16)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f, ok := AsNumber(doc.Root)
	if !ok || f != 8165 {
		t.Errorf("root = %#v, want the literal 8165", doc.Root)
	}
}

// TestDecodeCycleTerminates verifies a self-referential payload terminates
// instead of exhausting the stack.
func TestDecodeCycleTerminates(t *testing.T) {
	// Entry 0 and entry 1 each hold a reference back to entry 1.
	doc, err := Decode([]byte(`[[1],[1]]`), 8)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	outer, ok := AsSlice(doc.Root)
	if !ok || len(outer) != 1 {
		t.Fatalf("root = %#v, want a one-element list", doc.Root)
	}
	inner, ok := AsSlice(outer[0])
	if !ok || len(inner) != 1 {
		t.Fatalf("root = %#v, want a nested one-element list", doc.Root)
	}
	if !IsCycle(inner[0]) {
		t.Fatalf("innermost value = %#v, want cycle marker", inner[0])
	}
}

// TestDecodeRejectsUnusableInput verifies malformed input is an error rather
// than a partially populated document that downstream code might trust.
func TestDecodeRejectsUnusableInput(t *testing.T) {
	cases := map[string]string{
		"empty":            ``,
		"not json":         `not json`,
		"object not array": `{}`,
		"dangling ref":     `[[5]]`,
		"nested dangling":  `[{"a":[9]}]`,
		"ref out of range": `[[2,3],3,4]`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(in), 16); err == nil {
				t.Errorf("Decode(%q) succeeded, want error", in)
			}
		})
	}
}

// TestDepthBound verifies a long chain of wrappers is rejected rather than
// recursing without limit.
func TestDepthBound(t *testing.T) {
	const depth = 60
	parts := make([]string, 0, depth+1)
	for i := 0; i < depth; i++ {
		parts = append(parts, "["+strconv.Itoa(i+1)+"]")
	}
	parts = append(parts, `"leaf"`)
	payload := "[" + joinComma(parts) + "]"

	if _, err := Decode([]byte(payload), 10); err == nil {
		t.Error("deep chain accepted at depth 10, want error")
	}
	if _, err := Decode([]byte(payload), depth*4); err != nil {
		t.Errorf("deep chain rejected at adequate depth: %v", err)
	}
}

// TestAccessorsPreserveAbsence verifies the typed accessors report presence
// rather than substituting defaults. Policy depends on this to keep unknown
// facts unknown.
func TestAccessorsPreserveAbsence(t *testing.T) {
	// Field values inside the flattened array are always indices, so
	// "wrongtype" points at a node holding a string.
	doc, err := Decode([]byte(`[{"present":1,"absent":-1,"wrongtype":2},true,"text"]`), 16)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	root, ok := AsMap(doc.Root)
	if !ok {
		t.Fatalf("root is %T", doc.Root)
	}

	if _, ok := AsBool(root["present"]); !ok {
		t.Error("AsBool reported a present bool as unknown")
	}
	if _, ok := AsBool(root["absent"]); ok {
		t.Error("AsBool reported an absent value as known")
	}
	if _, ok := AsBool(root["wrongtype"]); ok {
		t.Error("AsBool accepted a string as a bool")
	}
	if _, ok := AsInt(root["absent"]); ok {
		t.Error("AsInt reported an absent value as known")
	}
	if got := AsString(root["absent"]); got != "" {
		t.Errorf("AsString of absent = %q, want empty", got)
	}
}

// TestFindTraversesWrappers verifies path lookup descends through reactive
// wrappers, which is how program records are nested.
func TestFindTraversesWrappers(t *testing.T) {
	payload := `[["Reactive",1],{"data":2},{"program":3},{"slug":4},"bitrue"]`
	doc, err := Decode([]byte(payload), 32)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Find is deliberately generic: it walks object keys and does not know
	// that this source happens to nest records under a "data" key. The
	// adapter supplies the concrete path.
	got, ok := Find(doc.Root, "data", "program", "slug")
	if !ok {
		t.Fatalf("Find did not locate data.program.slug in %#v", doc.Root)
	}
	if AsString(got) != "bitrue" {
		t.Errorf("slug = %q, want bitrue", AsString(got))
	}
	if _, ok := Find(doc.Root, "data", "program", "missing"); ok {
		t.Error("Find located a key that does not exist")
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

var _ = fmt.Sprintf
