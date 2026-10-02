// Package devalue decodes the flattened reference format that the source's
// server-side renderer embeds in its HTML.
//
// The format is a single JSON array in which every value is hoisted and every
// composite value is a list of indices into that array. Two scalar encodings
// matter here: -1 means "absent" rather than zero, and -3 means NaN. Getting
// those wrong would turn a missing access gate into a zero-point requirement,
// which is precisely the failure this system is built to avoid.
//
// Decoding is total: any construct the decoder does not recognise is reported
// rather than guessed at.
package devalue

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Special negative indices used by the format for values that are not
// references. Getting this table wrong would turn an absent value into a real
// one, so it is spelled out explicitly rather than derived.
const (
	negUndefined    = -1 // hole / absent
	negNaN          = -2
	negInfinity     = -3
	negNegInfinity  = -4
	negNegativeZero = -5
)

// wrapperNames are list or object tags that indicate a reactive container
// rather than a real value. They are transparent to callers.
var wrapperNames = map[string]struct{}{
	"reactive":           {},
	"shallowreactive":    {},
	"shallowref":         {},
	"ref":                {},
	"set":                {},
	"map":                {},
	"raw":                {},
	"promise":            {},
	"shallowreadonlyraw": {},
}

// Node is a decoded value. Map and Slice alias the decoded structures.
type Node = any

// Document is a decoded payload.
type Document struct {
	// Root is the decoded top-level value.
	Root Node

	// Nodes is the raw hoisted array, retained so that a caller can resolve
	// additional references if needed.
	Nodes []any
}

// Decode parses the flattened JSON array.
//
// maxDepth bounds recursion. A deeply self-referential payload would otherwise
// be able to exhaust the stack; bounding it converts that into an ordinary
// error.
func Decode(raw []byte, maxDepth int) (*Document, error) {
	if maxDepth <= 0 {
		maxDepth = 64
	}
	var nodes []any
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, fmt.Errorf("devalue: parse: %w", err)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("devalue: empty payload")
	}

	d := &decoder{nodes: nodes, maxDepth: maxDepth}
	// Entry 0 of the hoisted array is the document root. It is a literal
	// value, not a reference.
	root, err := d.node(nodes[0], map[int]bool{}, 0)
	if err != nil {
		return nil, err
	}
	return &Document{Root: d.unwrap(root), Nodes: nodes}, nil
}

type decoder struct {
	nodes    []any
	maxDepth int
}

// resolve converts one hoisted node into a plain Go value.
func (d *decoder) resolve(index int, seen map[int]bool, depth int) (Node, error) {
	if depth > d.maxDepth {
		return nil, fmt.Errorf("devalue: nesting exceeds %d levels", d.maxDepth)
	}
	if index < 0 || index >= len(d.nodes) {
		return nil, fmt.Errorf("devalue: reference %d out of range (%d nodes)", index, len(d.nodes))
	}
	if seen[index] {
		// A cycle is legitimate in a document graph but cannot be represented
		// as a plain tree. Returning a marker keeps decoding total and makes
		// the cycle visible to the caller instead of looping.
		return cycleMarker, nil
	}
	seen[index] = true
	defer delete(seen, index)
	return d.node(d.nodes[index], seen, depth+1)
}

// value interprets a number appearing inside a composite, where it is a
// reference to another entry or one of the negative special encodings.
func (d *decoder) value(v any, seen map[int]bool, depth int) (Node, error) {
	f, ok := v.(float64)
	if !ok {
		return nil, fmt.Errorf("devalue: unexpected node type %T", v)
	}
	if f < 0 {
		switch int(f) {
		case negUndefined:
			// An absent value. Returning nil keeps "the source did not say"
			// distinguishable from "the source said zero".
			return nil, nil
		case negNaN:
			return math.NaN(), nil
		case negInfinity:
			return math.Inf(1), nil
		case negNegInfinity:
			return math.Inf(-1), nil
		case negNegativeZero:
			return math.Copysign(0, -1), nil
		default:
			// Any other negative index is a literal negative number.
			return f, nil
		}
	}
	return d.resolve(int(f), seen, depth)
}

// node decodes one hoisted entry of the array.
//
// The distinction that matters here: an entry is a literal value, while numbers
// appearing *inside* a composite (an object field or a list element) are
// references to other entries. The source stores real values directly - a
// scope revision of 8165 sits in the array as the number 8165, not as a
// reference - so treating every number as a reference would try to resolve a
// literal as an index and fail on real data.
func (d *decoder) node(v any, seen map[int]bool, depth int) (Node, error) {
	switch t := v.(type) {
	case []any:
		return d.list(t, seen, depth)
	case map[string]any:
		return d.object(t, seen, depth)
	default:
		// Numbers, strings, booleans and null are stored literally.
		return v, nil
	}
}

// cycleMarker stands in for a value that refers back to an ancestor.
const cycleMarker = "<cycle>"

// IsCycle reports whether a decoded value is the cycle marker.
func IsCycle(v Node) bool {
	s, ok := v.(string)
	return ok && s == cycleMarker
}

func (d *decoder) list(items []any, seen map[int]bool, depth int) (Node, error) {
	// A two-element list whose head is a known wrapper tag is a transparent
	// container, not a real sequence. Its payload is a reference.
	if len(items) == 2 {
		if tag, ok := items[0].(string); ok {
			if _, wrapped := wrapperNames[strings.ToLower(tag)]; wrapped {
				return d.value(items[1], seen, depth+1)
			}
		}
	}
	// A one-element list is transparent only when it merely names a wrapper,
	// as in ["Set"] for an empty collection. A one-element list holding
	// anything else is a genuine single-element sequence, which is common in
	// the source's label lists.
	if len(items) == 1 {
		if tag, ok := items[0].(string); ok {
			if _, wrapped := wrapperNames[strings.ToLower(tag)]; wrapped {
				return tag, nil
			}
		}
	}

	out := make([]any, 0, len(items))
	for _, item := range items {
		decoded, err := d.value(item, seen, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, decoded)
	}
	return out, nil
}

func (d *decoder) object(fields map[string]any, seen map[int]bool, depth int) (Node, error) {
	// A single-field object keyed by a wrapper tag is transparent.
	if len(fields) == 1 {
		for k, v := range fields {
			if _, wrapped := wrapperNames[strings.ToLower(k)]; wrapped {
				return d.value(v, seen, depth+1)
			}
		}
	}

	out := make(map[string]any, len(fields))
	for k, raw := range fields {
		decoded, err := d.value(raw, seen, depth+1)
		if err != nil {
			return nil, err
		}
		out[k] = decoded
	}
	return out, nil
}

// unwrap removes any remaining wrapper objects so that callers see plain data.
func (d *decoder) unwrap(v Node) Node {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, d.unwrap(e))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if _, skip := skipFields[k]; skip {
				continue
			}
			out[k] = d.unwrap(e)
		}
		return out
	default:
		return v
	}
}

// skipFields are framework bookkeeping that carries no program data.
var skipFields = map[string]struct{}{
	"$ssite-config": {},
	"_priority":     {},
}

// AsMap returns v as a mapping when possible.
func AsMap(v Node) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// AsSlice returns v as a list when possible.
func AsSlice(v Node) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// AsString returns v as a string, or "" when it is absent or another type.
func AsString(v Node) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// AsBool returns v as a bool, reporting whether the value was actually a bool.
// A missing field yields ok=false so that callers can keep the fact unknown
// rather than defaulting it to false.
func AsBool(v Node) (value bool, ok bool) {
	b, isBool := v.(bool)
	return b, isBool
}

// AsNumber returns v as a float, reporting whether it was numeric.
func AsNumber(v Node) (value float64, ok bool) {
	f, isNum := v.(float64)
	return f, isNum
}

// AsInt returns v as an int when it is a whole number.
func AsInt(v Node) (value int, ok bool) {
	f, isNum := v.(float64)
	if !isNum {
		return 0, false
	}
	if f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

// Find walks a nested structure and returns the first mapping found under path.
//
// Path elements are object keys. A path element of "" addresses a list, taking
// its first element, which is how the source nests most program records.
func Find(v Node, path ...string) (Node, bool) {
	cur := v
	for _, key := range path {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[key]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			if len(node) == 0 {
				return nil, false
			}
			// A list in a path position is traversed via its first element.
			cur = node[0]
			m, ok := node[0].(map[string]any)
			if !ok {
				return nil, false
			}
			next, ok := m[key]
			if !ok {
				return nil, false
			}
			cur = next
		default:
			return nil, false
		}
	}
	return cur, true
}

// FormatNumber renders a numeric node for display without scientific notation
// or trailing zeros, which the source's own formatting is inconsistent about.
func FormatNumber(v Node) string {
	f, ok := AsNumber(v)
	if !ok {
		return AsString(v)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}
