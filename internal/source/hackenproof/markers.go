package hackenproof

import (
	"regexp"
	"strings"
)

var (
	// htmlCommentRe removes the comment nodes the renderer leaves between
	// elements. They carry no visible text, but they do carry the words the
	// page is built from, and reading a marker out of a comment would be
	// reading the template rather than the page.
	htmlCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

	// htmlTagRe removes the tags themselves, leaving the text a reader sees.
	htmlTagRe = regexp.MustCompile(`(?s)<[^>]*>`)

	// htmlSpaceRe collapses the whitespace the markup introduces.
	htmlSpaceRe = regexp.MustCompile(`\s+`)

	// programLeftRe matches the rendered "Program left N days ago" statement.
	programLeftRe = regexp.MustCompile(`Program left\s+((?:[A-Za-z0-9]+\s+)*ago)`)
)

// pageMarkers extracts the human-visible lifecycle statements from a rendered
// program page.
//
// It reports only what it can see. A program that is still running shows no
// liveness badge and no departure date, so nothing is reported for it: the
// absence of a marker is not evidence of anything, and inventing a positive
// marker for an open program would put a claim in an alert that no page
// supports.
func pageMarkers(body []byte) map[string]string {
	text := htmlSpaceRe.ReplaceAllString(
		htmlTagRe.ReplaceAllString(htmlCommentRe.ReplaceAllString(string(body), " "), " "), " ")

	markers := map[string]string{}

	if m := programLeftRe.FindStringSubmatch(text); m != nil {
		markers["program_left"] = m[1]

		// The liveness badge sits immediately before the departure statement.
		idx := strings.Index(text, "Program left")
		if idx > 0 {
			back := text[max(0, idx-80):idx]
			if fields := strings.Fields(back); len(fields) > 0 {
				word := fields[len(fields)-1]
				if word != "" && word[0] >= 'A' && word[0] <= 'Z' {
					markers["liveness_badge"] = word
				}
			}
		}
	}

	switch {
	case strings.Contains(text, "Contest is not active"):
		markers["contest_notice"] = "not active"
	case strings.Contains(text, "Contest is active"):
		markers["contest_notice"] = "active"
	}

	if len(markers) == 0 {
		return nil
	}
	return markers
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
