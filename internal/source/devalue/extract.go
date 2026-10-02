package devalue

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrNoPayload reports that the page did not contain an embedded payload.
//
// It is a distinct error because it almost always means the upstream site
// changed its rendering rather than that the network failed, and the two demand
// different responses.
var ErrNoPayload = errors.New("devalue: embedded payload not found")

// payloadMarker is the id of the script element holding the payload.
var payloadMarker = []byte(`id="__NUXT_DATA__"`)

// ExtractPayload returns the raw JSON array embedded in a rendered page.
//
// The payload sits in a single script element. Extraction is byte-oriented and
// tolerant of attribute ordering, because the surrounding markup carries no
// information this system needs and re-parsing it as HTML would add a
// dependency for no benefit.
func ExtractPayload(page []byte) ([]byte, error) {
	if len(page) == 0 {
		return nil, ErrNoPayload
	}

	marker := bytes.Index(page, payloadMarker)
	if marker < 0 {
		return nil, ErrNoPayload
	}

	// The JSON begins after the closing angle bracket of the opening tag.
	open := bytes.IndexByte(page[marker:], '>')
	if open < 0 {
		return nil, fmt.Errorf("%w: malformed script tag", ErrNoPayload)
	}
	start := marker + open + 1

	// The JSON is raw script content, not an HTML attribute, so the first
	// closing tag ends it. A literal "</script>" cannot appear inside the
	// payload because the encoder escapes it.
	end := bytes.Index(page[start:], []byte("</script>"))
	if end < 0 {
		return nil, fmt.Errorf("%w: unterminated script tag", ErrNoPayload)
	}

	payload := bytes.TrimSpace(page[start : start+end])
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: payload is empty", ErrNoPayload)
	}
	if payload[0] != '[' {
		return nil, fmt.Errorf("%w: payload is not a JSON array", ErrNoPayload)
	}
	return payload, nil
}
