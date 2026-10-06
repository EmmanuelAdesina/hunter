package tui

import "strings"

// asciiFold maps every unicode glyph the theme can emit to its ASCII
// counterpart. Components already select glyph sets per mode; this covers
// literal text in screens so --ascii output is pure 7-bit.
var asciiFold = strings.NewReplacer(
	"─", "-", "│", "|", "┌", "+", "┐", "+", "└", "+", "┘", "+",
	"◈", "*", "◆", "*", "●", "o", "◐", "o", "✓", "v", "✕", "x",
	"→", "->", "·", "-", "—", "-", "…", ">", "┄", ".", "≠", "!=",
)

// FoldASCII rewrites themed output into pure ASCII. It is a no-op for text
// that is already ASCII. Only fixed-budget lines must avoid multi-cell
// expansions (only "→" expands, and it never appears in one).
func FoldASCII(s string) string { return asciiFold.Replace(s) }
