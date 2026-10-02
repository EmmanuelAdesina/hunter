// Package canon produces canonical, byte-stable JSON encodings.
//
// Determinism is a hard requirement: state files live in git, fingerprints are
// compared across runs, and tests assert on serialized output. Go's
// encoding/json already sorts map keys and emits struct fields in declaration
// order, so the only adjustments needed are disabling HTML escaping (which
// would otherwise mangle the "<" and "&" that appear constantly in program
// descriptions) and rejecting values JSON cannot represent.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
)

// Marshal encodes v as canonical JSON: no HTML escaping, no trailing newline.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canon: encode: %w", err)
	}
	out := buf.Bytes()
	// Encode appends a newline; strip it so callers can embed the result.
	return bytes.TrimRight(out, "\n"), nil
}

// MarshalIndent encodes v as canonical, human-reviewable JSON. Indentation is
// used only where a human or a diff is expected to read the output.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent(prefix, indent)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canon: encode: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Valid reports whether f is a finite number and therefore safe to encode.
func Valid(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
