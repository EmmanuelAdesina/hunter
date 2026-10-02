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
		{"empty set is transparent", `[["Set"]]`, "Set"},
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

// TestDecodeSpecialNumbers verifies the negative-index specials decode to the
// values they stand for. They appear inside a composite, because that is where
// a reference is valid.
func TestDecodeSpecialNumbers(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		check   func(t *testing.T, v any)
	}{
		{"NaN", `[[-2]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsNaN(f) {
				t.Errorf("got %#v, want NaN", v)
			}
		}},
		{"positive infinity", `[[-3]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsInf(f, 1) {
				t.Errorf("got %#v, want +Inf", v)
			}
		}},
		{"negative infinity", `[[-4]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || !math.IsInf(f, -1) {
				t.Errorf("got %#v, want -Inf", v)
			}
		}},
		{"negative literal reference", `[[-15]]`, func(t *testing.T, v any) {
			f, ok := v.(float64)
			if !ok || f != -15 {
				t.Errorf("got %#v, want -15", v)
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
