// Package tui renders the Reliastra Obsidian Executive terminal theme.
//
// It is stdlib-only and render-only: no business logic, no state, and no I/O
// beyond the strings it returns. Width math counts printable cells; ANSI
// sequences are never counted. Every glyph has a single-cell ASCII fallback,
// and every color degrades to a bracketed label when color is off, so output
// stays legible under NO_COLOR, dumb terminals, and monochrome logs.
package tui

import (
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Foreground SGR fragments (truecolor).
const (
	FGText   = "38;2;230;234;242"
	FGMuted  = "38;2;139;148;169"
	FGFaint  = "38;2;74;84;104"
	FGGold   = "38;2;232;200;122"
	FGTeal   = "38;2;94;234;212"
	FGGreen  = "38;2;52;211;153"
	FGSky    = "38;2;125;211;252"
	FGAmber  = "38;2;251;191;36"
	FGRose   = "38;2;251;113;133"
	FGViolet = "38;2;167;139;250"
	FGHair   = "38;2;110;95;60" // dim gold for hairlines
	FGInk    = "38;2;8;10;16"   // text on solid chips
)

// Style fragments.
const (
	Bold = "1"
	Dim  = "2"
)

// Solid chip backgrounds.
const (
	PBGold   = "48;2;232;200;122"
	PBGreen  = "48;2;52;211;153"
	PBSky    = "48;2;125;211;252"
	PBAmber  = "48;2;251;191;36"
	PBRose   = "48;2;251;113;133"
	PBTeal   = "48;2;94;234;212"
	PBViolet = "48;2;167;139;250"
	PBGray   = "48;2;74;84;104"
)

// DefaultWidth is the design canvas. Layouts are composed for it and narrow
// gracefully; content truncates, never wraps mid-glyph.
const DefaultWidth = 96

// Mode selects rendering capabilities.
type Mode struct {
	Color   bool // ANSI SGR sequences emitted
	Unicode bool // unicode glyphs; false selects ASCII fallbacks
	Width   int  // canvas columns, clamped to [60,200]
}

// Auto derives a mode from the environment: NO_COLOR disables color, a dumb
// terminal also disables unicode, and COLUMNS overrides the width.
func Auto() Mode {
	m := Mode{Color: true, Unicode: true, Width: DefaultWidth}
	if os.Getenv("NO_COLOR") != "" {
		m.Color = false
	}
	if os.Getenv("TERM") == "dumb" {
		m.Color = false
		m.Unicode = false
	}
	if v := strings.TrimSpace(os.Getenv("COLUMNS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			m.Width = n
		}
	}
	return m.normalized()
}

// normalized clamps the width into the supported range.
func (m Mode) normalized() Mode {
	if m.Width <= 0 {
		m.Width = DefaultWidth
	}
	if m.Width < 60 {
		m.Width = 60
	}
	if m.Width > 200 {
		m.Width = 200
	}
	return m
}

// T is a themed renderer bound to one mode.
type T struct{ Mode Mode }

// New returns a renderer for m, normalizing the width.
func New(m Mode) *T {
	m = m.normalized()
	return &T{Mode: m}
}

// Paint wraps s in the given SGR fragments ("1", "38;2;1;2;3", ...).
// It returns s unchanged when color is off or no code is given.
func (t *T) Paint(codes, s string) string {
	if !t.Mode.Color || codes == "" {
		return s
	}
	return "\x1b[" + codes + "m" + s + "\x1b[0m"
}

// Glyphs are the drawing characters for the active mode. Every glyph is a
// single cell in virtually all terminals; nothing here is emoji.
type Glyphs struct {
	H, V, TL, TR, BL, BR string
	Star, Diamond, Dot   string
	Check, Arrow, Mid    string
	Full, Empty          string
}

// G returns the glyph set for the mode.
func (t *T) G() Glyphs {
	if !t.Mode.Unicode {
		return Glyphs{
			H: "-", V: "|", TL: "+", TR: "+", BL: "+", BR: "+",
			Star: "*", Diamond: "*", Dot: "o",
			Check: "v", Arrow: "->", Mid: "-",
			Full: "#", Empty: "-",
		}
	}
	return Glyphs{
		H: "─", V: "│", TL: "┌", TR: "┐", BL: "└", BR: "┘",
		Star: "◈", Diamond: "◆", Dot: "●",
		Check: "✓", Arrow: "→", Mid: "·",
		Full: "█", Empty: "░",
	}
}

// Em returns an em dash, or "-" in ASCII mode.
func (t *T) Em() string {
	if !t.Mode.Unicode {
		return "-"
	}
	return "—"
}

// Dot returns the leader dot for key/value rows.
func (t *T) Dot() string {
	if !t.Mode.Unicode {
		return "."
	}
	return "┄"
}

// Visible returns the printable width of s: runes minus ANSI SGR sequences.
// The renderer only emits SGR (ESC [ ... m), so only that form is skipped.
func Visible(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++ // consume 'm'
			}
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

// PadRight pads paint-free or painted text with spaces to w cells.
func PadRight(s string, w int) string {
	if d := w - Visible(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// Truncate cuts paint-free text to w cells with a mode-aware marker.
// Callers must truncate before painting.
func (t *T) Truncate(s string, w int) string {
	if utf8.RuneCountInString(s) <= w {
		return s
	}
	mark := "…"
	if !t.Mode.Unicode {
		mark = ">"
	}
	if w <= 1 {
		return mark
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= w-1 {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String() + mark
}

// Rule is a full-width faint hairline.
func (t *T) Rule() string {
	return t.Paint(FGFaint, strings.Repeat(t.G().H, t.Mode.Width))
}

// Section renders "LABEL ───…" across the full width.
func (t *T) Section(label string) string {
	pad := t.Mode.Width - Visible(label) - 1
	if pad < 2 {
		pad = 2
	}
	return t.Paint(FGFaint, label+" ") + t.Paint(FGHair, strings.Repeat(t.G().H, pad))
}

// Box frames lines in a bordered panel. The title rides the top border and
// the border color is a single SGR fragment (FGGold, FGGreen, ...).
func (t *T) Box(title string, lines []string, border string) string {
	g := t.G()
	w := t.Mode.Width
	inner := w - 4
	var b strings.Builder
	dashes := w - 5 - Visible(title)
	if dashes < 2 {
		dashes = 2
	}
	b.WriteString(t.Paint(border, g.TL+g.H+" "))
	b.WriteString(title)
	b.WriteString(t.Paint(border, " "+strings.Repeat(g.H, dashes)+g.TR))
	b.WriteString("\n")
	for _, ln := range lines {
		b.WriteString(t.Paint(border, g.V+" "))
		b.WriteString(PadRight(ln, inner))
		b.WriteString(t.Paint(border, " "+g.V))
		b.WriteString("\n")
	}
	b.WriteString(t.Paint(border, g.BL+strings.Repeat(g.H, w-2)+g.BR))
	return b.String()
}

// Pill renders a solid status chip (" NEW "). Without color it degrades to
// a bracketed label ("[NEW]") so meaning never depends on hue.
func (t *T) Pill(bg, fg, label string) string {
	if !t.Mode.Color {
		return "[" + label + "]"
	}
	return "\x1b[" + bg + ";" + fg + "m " + label + " \x1b[0m"
}

// Bar renders a fractional meter w cells wide.
func (t *T) Bar(frac float64, w int, color string) string {
	g := t.G()
	if w <= 0 {
		return ""
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	full := int(frac*float64(w) + 0.5)
	return t.Paint(color, strings.Repeat(g.Full, full)+strings.Repeat(g.Empty, w-full))
}

// KeyVal renders "key ┄┄┄ value" across w cells with dotted leaders.
func (t *T) KeyVal(key, value string, w int) string {
	n := w - Visible(key) - Visible(value) - 2
	if n < 2 {
		n = 2
	}
	return t.Paint(FGMuted, key) + " " + t.Paint(FGFaint, strings.Repeat(t.Dot(), n)) + " " + value
}

// Cells joins pre-padded columns with faint separators.
func (t *T) Cells(cols []string) string {
	return strings.Join(cols, t.Paint(FGFaint, " "+t.G().V+" "))
}
