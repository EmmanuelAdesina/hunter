package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/eadeshina/hunter/internal/tui"
)

// cmdDemo renders the Reliastra Obsidian Executive preview screens with fixed
// mock evidence. It is a design-review instrument: it reads no profile, keeps
// no state, and touches no network. It will be removed (or hidden) once the
// theme ships on the real commands.
func cmdDemo(env *Env, args []string) int {
	var (
		screen  string
		list    bool
		noColor bool
		ascii   bool
		width   int
		animate bool
	)
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.StringVar(&screen, "screen", "all", "one screen to render (see --list), or 'all'")
	fs.BoolVar(&list, "list", false, "list available screens")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI color")
	fs.BoolVar(&ascii, "ascii", false, "use ASCII glyphs instead of unicode")
	fs.IntVar(&width, "width", 0, "canvas width in columns (default 96, honors COLUMNS)")
	fs.BoolVar(&animate, "animate", false, "animate the scan-live phase rail")
	if !parseFlags(fs, env, args) {
		return exitFailure
	}

	mode := tui.Auto()
	if noColor {
		mode.Color = false
	}
	if ascii {
		mode.Unicode = false
	}
	if width > 0 {
		mode.Width = width
	}
	t := tui.New(mode)

	screens := demoScreens()
	if list {
		for _, s := range screens {
			fmt.Fprintln(env.Stdout, s.name)
		}
		return exitOK
	}

	if animate {
		return demoAnimate(env, t)
	}

	if screen == "all" {
		for i, s := range screens {
			if i > 0 {
				fmt.Fprintln(env.Stdout)
				fmt.Fprintln(env.Stdout, t.Rule())
				fmt.Fprintln(env.Stdout)
			}
			fmt.Fprintln(env.Stdout, demoPrompt(t, s.cmd))
			fmt.Fprintln(env.Stdout, demoOut(t, s.render(t)))
		}
		fmt.Fprintln(env.Stdout)
		fmt.Fprintln(env.Stdout, demoOut(t,
			t.Paint(tui.FGFaint, "◈ end of demo · "+fmt.Sprint(len(screens))+
				" screens · --screen <name> renders one · --animate runs the live rail")))
		return exitOK
	}
	for _, s := range screens {
		if s.name == screen {
			fmt.Fprintln(env.Stdout, demoPrompt(t, s.cmd))
			fmt.Fprintln(env.Stdout, demoOut(t, s.render(t)))
			return exitOK
		}
	}
	fmt.Fprintf(env.Stderr, "demo: unknown screen %q (see --list)\n", screen)
	return exitFailure
}

// demoOut applies the ASCII fold when unicode is off, so --ascii output
// is pure 7-bit even where screens contain literal unicode separators.
func demoOut(t *tui.T, s string) string {
	if t.Mode.Unicode {
		return s
	}
	return tui.FoldASCII(s)
}

// demoScreen is one preview screen: its selector name, the typed command
// shown above it, and the renderer.
type demoScreen struct {
	name   string
	cmd    string
	render func(*tui.T) string
}

// demoScreens returns the preview catalogue in narrative order.
func demoScreens() []demoScreen {
	return []demoScreen{
		{name: "scan-live", cmd: "scan --profile personal", render: demoScanLive},
		{name: "scan-report", cmd: "scan", render: demoScanReport},
		{name: "programs", cmd: "programs --eligible --limit 6", render: demoPrograms},
		{name: "explain", cmd: "explain 1inch-business", render: demoExplain},
		{name: "windows", cmd: "windows --open", render: demoWindows},
		{name: "alerts", cmd: "alerts --limit 6", render: demoAlerts},
		{name: "validate", cmd: "validate-config", render: demoValidate},
		{name: "help", cmd: "help", render: demoHelp},
	}
}

// demoPrompt renders the typed command line above a screen.
func demoPrompt(t *tui.T, cmd string) string {
	head, tail := cmd, ""
	if i := strings.Index(cmd, " "); i >= 0 {
		head, tail = cmd[:i], cmd[i:]
	}
	return t.Paint(tui.FGFaint, "$ ") + t.Paint(tui.Bold, "reliastra") +
		" " + t.Paint(tui.FGGold, head) + t.Paint(tui.FGMuted, tail)
}

// demoAnimate replays the scan-live phase rail as a short animation.
func demoAnimate(env *Env, t *tui.T) int {
	const frames = 13
	for f := 0; f < frames; f++ {
		fracs := [7]float64{}
		for i := range fracs {
			// Phase i starts at frame i and completes four frames later;
			// discovery is already done when the operator looks.
			p := float64(f-i) / 4.0
			if p < 0 {
				p = 0
			}
			if p > 1 {
				p = 1
			}
			fracs[i] = p
		}
		fracs[0] = 1
		discovered := min(324, f*30)
		eligible := min(156, f*14)
		fmt.Fprint(env.Stdout, "\x1b[2J\x1b[H")
		fmt.Fprintln(env.Stdout, demoPrompt(t, "scan --profile personal"))
		fmt.Fprintln(env.Stdout, demoOut(t, renderScanLive(t, fracs, discovered, eligible,
			min(1, f/11), min(4, f/3), min(1, f/12))))
		time.Sleep(130 * time.Millisecond)
	}
	return exitOK
}

// ── shared mock facts (mirroring recorded state) ───────────────────────────

const (
	demoScanID = "20261006T191500Z"
	demoSource = "hackenproof"
	demoDur    = "38.8s"
)

// ── 01 scan-live ───────────────────────────────────────────────────────────

var demoPhaseNames = [7]string{"DISCOVER", "FETCH", "DIFF", "POLICY", "SCORE", "ALERT", "PERSIST"}

var demoPhaseDone = [7]string{
	"324/324 · 33 pages · 4.2s",
	"54/75 · catch-up · polite 750ms",
	"5 material · 11 minor",
	"156 eligible · 168 rejected",
	"priority 0-89",
	"1 armed · smtp ready",
	"state + history + windows",
}

// demoScanLive renders the frozen mid-run frame used by --screen scan-live.
func demoScanLive(t *tui.T) string {
	return renderScanLive(t,
		[7]float64{1, 0.72, 0.41, 0.3, 0.12, 0, 0},
		324, 156, 1, 4, 1)
}

// renderScanLive renders the phase rail at any progress: static preview and
// animation share it so the recording and the replay cannot drift apart.
func renderScanLive(t *tui.T, fracs [7]float64, discovered, eligible, freshNew, changed, armed int) string {
	g := t.G()
	var b strings.Builder

	title := t.Paint(tui.FGGold, g.Star+" RELIASTRA "+t.Em()+" OPPORTUNITY SWEEP")
	meta := t.Paint(tui.FGMuted, "profile ") + "personal" +
		t.Paint(tui.FGMuted, " · source ") + demoSource +
		t.Paint(tui.FGMuted, " · scan ") + demoScanID +
		"  " + t.Pill(tui.PBGold, tui.FGInk, "LIVE")
	b.WriteString(t.Box(title, []string{meta}, tui.FGGold))
	b.WriteString("\n")

	// Phase rail: 2 + 9 + 2 + 16 + 1 + 52 + 14 = 96.
	for i, name := range demoPhaseNames {
		frac := fracs[i]
		detail := "queued"
		status := t.Paint(tui.FGFaint, "QUEUED")
		switch {
		case frac >= 1:
			detail = demoPhaseDone[i]
			status = t.Paint(tui.FGGreen, g.Check+" DONE")
		case frac > 0:
			detail = fmt.Sprintf("%d%% · %s", int(frac*100+0.5), demoPhaseDone[i])
			status = t.Paint(tui.FGGold, g.Dot+" LIVE")
		}
		line := "  " + tui.PadRight(t.Paint(tui.Bold, name), 9) + "  " +
			t.Bar(frac, 16, tui.FGGold) + " " +
			tui.PadRight(t.Paint(tui.FGMuted, t.Truncate(detail, 52)), 52) +
			tui.PadRight(status, 14)
		b.WriteString(line + "\n")
	}
	b.WriteString(t.Section("LIVE COUNTERS") + "\n")

	cell := func(label, value, color string) string {
		return tui.PadRight(t.Paint(tui.FGMuted, label+" ")+t.Paint(color, value), 20)
	}
	counters := t.Cells([]string{
		cell("DISCOVERED", fmt.Sprint(discovered), tui.FGSky),
		cell("ELIGIBLE", fmt.Sprint(eligible), tui.FGGreen),
		cell("NEW·CHG", fmt.Sprintf("%d·%d", freshNew, changed), tui.FGGold),
		cell("ARMED", fmt.Sprint(armed), tui.FGGold),
	})
	b.WriteString(t.Box(t.Paint(tui.FGFaint, "COUNTERS"), []string{counters}, tui.FGFaint) + "\n")
	b.WriteString(t.Paint(tui.FGFaint, g.Dot+" polite 750ms "+g.Mid+" 4 workers "+
		g.Mid+" esc aborts cleanly "+t.Em()+" state is never half-written"))
	return b.String()
}

// ── 02 scan-report ─────────────────────────────────────────────────────────

func demoScanReport(t *tui.T) string {
	g := t.G()
	var b strings.Builder

	verdict := []string{
		t.Paint(tui.FGGold+";"+tui.Bold, g.Diamond+" 1 ACTIONABLE OPPORTUNITY"),
		"delivered "+t.Paint(tui.Bold, "1/1")+
			t.Paint(tui.FGMuted, " · suppressed 0 · errors 0 · exit ") +
			t.Paint(tui.Bold, "0") +
			t.Paint(tui.FGMuted, " · coverage ") +
			t.Paint(tui.FGGreen+";"+tui.Bold, "100% TRUSTED"),
		"scan "+demoScanID+t.Paint(tui.FGMuted, " · "+demoDur+" · source "+demoSource),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, g.Star+" VERDICT"), verdict, tui.FGGold) + "\n")

	cell := func(label, value, color string) string {
		return tui.PadRight(t.Paint(tui.FGMuted, label+" ")+t.Paint(color, value), 20)
	}
	sweep := t.Cells([]string{
		cell("EVALUATED", "324", tui.FGSky),
		cell("ELIGIBLE", "156", tui.FGGreen),
		cell("NEW·CHG·MIN", "1·4·11", tui.FGGold),
		cell("ERRORS", "0", tui.FGText),
	})
	b.WriteString(t.Box(t.Paint(tui.FGFaint, "SWEEP"), []string{sweep}, tui.FGFaint) + "\n")

	b.WriteString(t.Section("COVERAGE "+t.Em()+" DID THIS SWEEP SEE THE PLATFORM?") + "\n")
	gauge := t.Paint(tui.FGGreen+";"+tui.Bold, g.Dot+" 100.0%") + " " +
		t.Bar(1, 38, tui.FGGreen) + "  " +
		t.Paint(tui.FGMuted, "324/324 · floor 90% · absent 0 · departed 2")
	b.WriteString(gauge + "\n")

	b.WriteString(t.Section("ALERT DISPATCHED") + "\n")
	alert := []string{
		t.Paint(tui.Bold, "Swisstronik Blockchain Stability"),
		t.Paint(tui.FGMuted, "launched 3y ago · detected <1m · 4 submissions · low competition"),
		t.Paint(tui.FGSky, "web2 · web_application · 6 in-scope assets"),
		t.Paint(tui.FGMuted, "why: no reputation gate · no fee · no KYC · crypto_platform"),
		t.Pill(tui.PBGreen, tui.FGInk, "SENT") + "  " +
			t.Paint(tui.FGTeal, "hackenproof.com/programs/swisstronik-blockchain-stability"),
	}
	b.WriteString(t.Box(
		t.Pill(tui.PBGold, tui.FGInk, "NEW MATCH")+" "+
			t.Paint(tui.FGMuted, "PRIO 87/100 · $500 CEILING"),
		alert, tui.FGGold) + "\n")

	b.WriteString(t.Section("ELIGIBLE · TOP 5 BY ATTENTION PRIORITY") + "\n")
	b.WriteString(demoTableHead(t, []demoCol{
		{"PROGRAM", 36}, {"SCORE", 14}, {"AGE", 6}, {"TOP REASON", 40},
	}) + "\n")
	type topRow struct {
		name   string
		score  int
		age    string
		reason string
	}
	for _, r := range []topRow{
		{"Ternoa Web and Apps", 89, "4y", "ceiling $50,000 · 10 assets"},
		{"Sweed Web", 88, "1y", "23 in-scope assets · infra+web"},
		{"Avalanche Websites and APIs", 87, "5y", "api · web · $10k ceiling"},
		{"Swisstronik Blockchain Stability", 87, "3y", "4 submissions · low competition"},
		{"1inch Business", 84, "1y", "api.1inch.com · SaaS platform"},
	} {
		frac := float64(r.score) / 100.0
		line := tui.PadRight(t.Paint(tui.FGGold, g.Diamond)+" "+r.name, 36) +
			tui.PadRight(t.Bar(frac, 8, tui.FGGold)+" "+t.Paint(tui.FGGold+";"+tui.Bold, fmt.Sprint(r.score)), 14) +
			tui.PadRight(t.Paint(tui.FGMuted, r.age), 6) +
			t.Paint(tui.FGMuted, t.Truncate(r.reason, 40))
		b.WriteString(line + "\n")
	}
	b.WriteString(t.Paint(tui.FGFaint, "+ 151 more eligible · reliastra programs --eligible "+
		" · machine-readable: --json"))
	return b.String()
}

// ── 03 programs ────────────────────────────────────────────────────────────

func demoPrograms(t *tui.T) string {
	var b strings.Builder
	head := []string{
		t.Paint(tui.FGMuted, "profile personal · 156 eligible of 324 known · scan "+demoScanID),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, "◈ PROGRAM LEDGER"), head, tui.FGGold) + "\n")
	b.WriteString(demoTableHead(t, []demoCol{
		{"PROGRAM", 36}, {"STATE", 13}, {"SCORE", 7}, {"LAUNCH/SEE", 12}, {"SURFACES", 28},
	}) + "\n")
	type progRow struct {
		name, sub  string
		pill       string
		score      int
		ages       string
		surfaces   string
	}
	rows := []progRow{
		{"1inch Business", "up to $100,000 · 163 reports", t.Pill(tui.PBGreen, tui.FGInk, "LIVE"), 84, "1y / 3d", "api · web_app"},
		{"Aurora Web", "up to $100,000 · 124 reports", t.Pill(tui.PBGreen, tui.FGInk, "LIVE"), 82, "3y / 3d", "web2 · web_app"},
		{"Ult: Trade Stocks & Crypto", "up to $20,000 · 74 reports", t.Pill(tui.PBGold, tui.FGInk, "NEW"), 81, "8d / 3d", "api · mobile"},
		{"WEEX Web & App", "up to $10,000 · 379 reports", t.Pill(tui.PBGreen, tui.FGInk, "LIVE"), 79, "1y / 3d", "web_app · mobile"},
		{"WhiteBIT", "up to $10,000 · 297 reports", t.Pill(tui.PBGreen, tui.FGInk, "LIVE"), 78, "5y / 3d", "api · web_app"},
		{"Astros Web", "up to $5,000 · 58 reports", t.Pill(tui.PBSky, tui.FGInk, "SCOPE+"), 76, "11m / 3d", "web_app"},
	}
	for _, r := range rows {
		b.WriteString(
			tui.PadRight(t.Paint(tui.Bold, t.Truncate(r.name, 36)), 36) +
				tui.PadRight(r.pill, 13) +
				tui.PadRight(t.Paint(tui.FGGold+";"+tui.Bold, fmt.Sprint(r.score)), 7) +
				tui.PadRight(t.Paint(tui.FGMuted, r.ages), 12) +
				t.Paint(tui.FGSky, t.Truncate(r.surfaces, 28)) + "\n")
		b.WriteString(t.Paint(tui.FGFaint, "  "+r.sub) + "\n")
	}
	b.WriteString(t.Paint(tui.FGFaint, "6 of 156 shown · reliastra explain <id> opens the dossier"))
	return b.String()
}

// ── 04 explain ─────────────────────────────────────────────────────────────

func demoExplain(t *tui.T) string {
	g := t.G()
	var b strings.Builder
	head := []string{
		t.Paint(tui.FGGreen+";"+tui.Bold, "ELIGIBLE") +
			t.Paint(tui.FGMuted, " · hackenproof · state live · confidence high"),
		t.Paint(tui.FGMuted, "priority ") + t.Paint(tui.FGGold+";"+tui.Bold, "84/100") +
			t.Paint(tui.FGMuted, " · bounty $100,000 · paid $34,200 · 163 reports"),
		t.Paint(tui.FGTeal, "hackenproof.com/programs/1inch-business"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGreen, g.Check+" DOSSIER · 1INCH BUSINESS"), head, tui.FGGreen) + "\n")

	b.WriteString(t.Section("ACCESS "+t.Em()+" CAN YOU REACH IT?") + "\n")
	ok := t.Paint(tui.FGGreen, g.Check+" ")
	for _, kv := range [][2]string{
		{"reputation", ok + "none required (<= 80 allowed)"},
		{"submission fee", ok + "none"},
		{"kyc", ok + "not required"},
		{"proof of concept", ok + "accepted"},
		{"paid to date", "$34,200 · 163 reports"},
	} {
		b.WriteString(t.KeyVal(kv[0], kv[1], t.Mode.Width) + "\n")
	}

	b.WriteString(t.Section("ATTACK SURFACE "+t.Em()+" 4 TARGETS") + "\n")
	b.WriteString(t.Paint(tui.FGSky, "api · web2 · web_application") +
		t.Paint(tui.FGMuted, " · capabilities: auth · accounts · trading") + "\n")
	for _, tg := range [][2]string{
		{"api", "api.1inch.com"},
		{"web", "business.1inch.com + /portal + /portal/documentation"},
	} {
		b.WriteString(t.Paint(tui.FGGreen, "+ ["+tg[0]+"]") + " " + tg[1] + "\n")
	}

	b.WriteString(t.Section("CRYPTO "+t.Em()+" PLATFORM, NOT PROTOCOL") + "\n")
	b.WriteString(t.KeyVal("kind", t.Paint(tui.FGTeal+";"+tui.Bold, "crypto_platform")+
		t.Paint(tui.FGMuted, " · ordinary software work"), t.Mode.Width) + "\n")
	b.WriteString(t.KeyVal("traits", t.Paint(tui.FGSky, "crypto_api · crypto_platform · crypto_web_application"), t.Mode.Width) + "\n")
	b.WriteString(t.KeyVal("dominance veto", t.Paint(tui.FGGreen, g.Check+" no excluded traits · 0% < 60% threshold"), t.Mode.Width) + "\n")

	b.WriteString(t.Section("POLICY CHECKS "+t.Em()+" EXPLAINED") + "\n")
	type check struct {
		chip, id, reason string
	}
	pass := t.Pill(tui.PBGreen, tui.FGInk, "PASS")
	info := t.Pill(tui.PBSky, tui.FGInk, "INFO")
	for _, c := range []check{
		{pass, "access.reputation", "no reputation required (<= 80 allowed)"},
		{pass, "access.kyc", "KYC not required"},
		{pass, "state.allowed", "live in {live, new}"},
		{pass, "surface.match", "exposes api, web2, web_application"},
		{pass, "crypto.allow", "carries crypto_platform + crypto_api"},
		{info, "timing.launch", "launched 1y ago · change window still evaluable"},
	} {
		line := c.chip + " " + tui.PadRight(t.Paint(tui.Bold, c.id), 20) +
			t.Paint(tui.FGMuted, t.Truncate(c.reason, t.Mode.Width-6-1-20-1))
		b.WriteString(line + "\n")
	}

	b.WriteString(t.Section("ATTENTION PRIORITY "+t.Em()+" ORDERING AID") + "\n")
	type pledge struct {
		name  string
		value int
		basis string
	}
	for _, p := range []pledge{
		{"freshness", 100, "first seen just now"},
		{"surface relevance", 100, "matches api, web2, web_application"},
		{"eligibility", 90, "9 of 10 requirements satisfied"},
		{"bounty", 85, "ceiling $100,000"},
		{"low competition", 46, "163 submissions reported"},
	} {
		color := tui.FGTeal
		if p.value < 90 {
			color = tui.FGGold
		}
		line := tui.PadRight(t.Paint(tui.FGMuted, p.name), 19) +
			tui.PadRight(t.Paint(tui.FGGold+";"+tui.Bold, fmt.Sprint(p.value)), 4) +
			t.Bar(float64(p.value)/100.0, 28, color) + " " +
			t.Paint(tui.FGFaint, t.Truncate(p.basis, t.Mode.Width-19-4-28-1))
		b.WriteString(line + "\n")
	}
	fp := func(h string) string { return t.Truncate(h, 9) }
	b.WriteString(t.Paint(tui.FGFaint, "fingerprints scope "+fp("57faf179357085ac")+
		" · requirements "+fp("4c6caf74c89214cb")+" · metadata "+fp("50a06a5186b73588")))
	return b.String()
}

// ── 05 windows ─────────────────────────────────────────────────────────────

func demoWindows(t *tui.T) string {
	g := t.G()
	var b strings.Builder

	w1 := []string{
		t.Paint(tui.FGMuted, "observed ") +
			t.Paint(tui.FGGold+";"+tui.Bold, "between 42m and 47m ago") +
			t.Paint(tui.FGMuted, " · opened by scan "+demoScanID),
		t.Paint(tui.FGMuted, "triggers ") +
			t.Pill(tui.PBSky, tui.FGInk, "SCOPE_EXPANSION") + " " +
			t.Pill(tui.PBTeal, tui.FGInk, "TARGET_ADDED"),
		t.Paint(tui.FGTeal, g.Diamond) + " + api.astros.ag entered scope " +
			t.Paint(tui.FGMuted, "[api]"),
		t.Paint(tui.FGTeal, g.Diamond) + " reward ceiling $3,000 " +
			t.Paint(tui.FGGold, g.Arrow) + " $5,000",
		t.Paint(tui.FGMuted, "submissions baseline 58 · current 58 · ") +
			t.Paint(tui.FGGreen+";"+tui.Bold, "+0 "+t.Em()+" uncrowded"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, "◐ OPEN · ASTROS WEB "+t.Em()+" SCOPE EXPANSION"), w1, tui.FGGold) + "\n")

	w2 := []string{
		t.Paint(tui.FGMuted, "observed ") +
			t.Paint(tui.FGGold+";"+tui.Bold, "between 3h and 3h 05m ago") +
			t.Paint(tui.FGMuted, " · launch-gated, source-reported"),
		t.Paint(tui.FGMuted, "triggers ") +
			t.Pill(tui.PBGold, tui.FGInk, "NEW_PROGRAM") + " " +
			t.Pill(tui.PBTeal, tui.FGInk, "NEWLY_ELIGIBLE"),
		t.Paint(tui.FGTeal, g.Diamond) + " first observed on listing page 1 · status NEW",
		t.Paint(tui.FGTeal, g.Diamond) + " access resolved: no gates · KYC for payout only",
		t.Paint(tui.FGMuted, "submissions baseline 70 · current 74 · ") +
			t.Paint(tui.FGAmber+";"+tui.Bold, "+4 "+t.Em()+" warming"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, "◐ OPEN · ULT: TRADE STOCKS & CRYPTO "+t.Em()+" NEWLY ELIGIBLE"), w2, tui.FGGold) + "\n")
	b.WriteString(t.Paint(tui.FGFaint, "2 open · closed windows stay queryable · reliastra replay <id> renders the timeline"))
	return b.String()
}

// ── 06 alerts ──────────────────────────────────────────────────────────────

func demoAlerts(t *tui.T) string {
	var b strings.Builder
	head := []string{
		t.Paint(tui.FGMuted, "every alert recorded · deduplicated by fingerprint · never announced twice"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, "◈ DELIVERY LEDGER · 5 OF 6 DELIVERED · SMTP READY"), head, tui.FGGold) + "\n")
	b.WriteString(demoTableHead(t, []demoCol{
		{"WHEN (UTC)", 17}, {"KIND", 15}, {"STATUS", 10}, {"PRIO", 6}, {"SUBJECT", 48},
	}) + "\n")
	type alertRow struct {
		when, kind, status string
		prio               int
		subject            string
	}
	rows := []alertRow{
		{"10-06 19:15:38", t.Pill(tui.PBGold, tui.FGInk, "NEW MATCH"), t.Pill(tui.PBGreen, tui.FGInk, "SENT"), 87, "Swisstronik Blockchain Stability — Web — <1m"},
		{"10-03 19:25:58", t.Pill(tui.PBGold, tui.FGInk, "NEW MATCH"), t.Pill(tui.PBGreen, tui.FGInk, "SENT"), 88, "Sweed Web — infra+web · 23 assets"},
		{"10-03 19:13:15", t.Pill(tui.PBSky, tui.FGInk, "SCOPE +"), t.Pill(tui.PBGreen, tui.FGInk, "SENT"), 86, "Astros Web — target added: api.astros.ag"},
		{"10-03 19:12:40", t.Pill(tui.PBGold, tui.FGInk, "NEW MATCH"), t.Pill(tui.PBGreen, tui.FGInk, "SENT"), 89, "Ternoa Web and Apps — $50k ceiling"},
		{"10-02 21:48:40", t.Pill(tui.PBSky, tui.FGInk, "SCOPE +"), t.Pill(tui.PBGreen, tui.FGInk, "SENT"), 84, "1inch Business — portal docs in scope"},
		{"10-02 21:44:39", t.Pill(tui.PBViolet, tui.FGInk, "RE-ACTIVATED"), t.Pill(tui.PBAmber, tui.FGInk, "RETRY 2"), 72, "Zest Protocol — listing republished"},
	}
	for _, r := range rows {
		subject := r.subject
		if !t.Mode.Unicode {
			subject = strings.ReplaceAll(subject, "—", "-")
		}
		b.WriteString(
			tui.PadRight(t.Paint(tui.FGMuted, r.when), 17) +
				tui.PadRight(r.kind, 15) +
				tui.PadRight(r.status, 10) +
				tui.PadRight(t.Paint(tui.FGGold+";"+tui.Bold, fmt.Sprint(r.prio)), 6) +
				t.Truncate(subject, 48) + "\n")
	}
	b.WriteString(t.Paint(tui.FGAmber, "last error: 421 smtp busy "+t.Em()+" next attempt in 5m") + "\n")
	b.WriteString(t.Paint(tui.FGFaint, "reliastra alerts --undelivered isolates pending"))
	return b.String()
}

// ── 07 validate ────────────────────────────────────────────────────────────

func demoValidate(t *tui.T) string {
	g := t.G()
	var b strings.Builder
	head := []string{
		t.Paint(tui.FGGreen+";"+tui.Bold, "VALID") +
			t.Paint(tui.FGMuted, " · configs/profiles/personal.yaml · 14/14 thresholds verified · exit 0"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGreen, g.Star+" PROFILE ATTESTED "+t.Em()+" PERSONAL"), head, tui.FGGreen) + "\n")

	b.WriteString(t.Section("ATTESTATION") + "\n")
	pass := t.Pill(tui.PBGreen, tui.FGInk, "PASS")
	for _, c := range []string{
		"sources · hackenproof enabled",
		"access gates · rep <= 80 · fee <= $5 · no KYC",
		"crypto mode auto · 8 allowed · 5 excluded · veto >= 60%",
		"coverage floor 90% · grace 2 sweeps",
		"windows · new 24h · change 72h · max age 168h",
	} {
		b.WriteString(pass + " " + t.Paint(tui.FGMuted, c) + "\n")
	}

	b.WriteString(t.Section("PROFILE LEDGER") + "\n")
	for _, kv := range [][2]string{
		{"target domains", "7 included"},
		{"accepted states", "live · new"},
		{"min alert severity", t.Paint(tui.FGAmber, "medium")},
		{"require eligible", t.Paint(tui.FGGreen, g.Check + " hard gate")},
		{"notifications", t.Paint(tui.FGGreen, g.Check+" enabled · cap 10/scan")},
		{"pacing", "750ms · 4 workers · 45s timeout"},
	} {
		b.WriteString(t.KeyVal(kv[0], kv[1], t.Mode.Width) + "\n")
	}
	b.WriteString(t.Paint(tui.FGFaint, "the coverage floor is printed here so exit 3 is always traceable"))
	return b.String()
}

// ── 08 help ────────────────────────────────────────────────────────────────

func demoHelp(t *tui.T) string {
	var b strings.Builder
	head := []string{
		t.Paint(tui.FGMuted, "hunter engine inside · zero-deps binary · --json stays byte-stable"),
	}
	b.WriteString(t.Box(t.Paint(tui.FGGold, "◈ RELIASTRA · SIGNAL OVER NOISE · V2.0.0"), head, tui.FGGold) + "\n")

	type cmd struct {
		name, flags, desc string
	}
	groups := []struct {
		title string
		cmds  []cmd
	}{
		{"OPERATE", []cmd{
			{"scan", "[--dry-run] [--no-details]", "Discover, evaluate, alert in one pass."},
			{"sync", "", "Alias for scan — the manual-run spelling."},
		}},
		{"INVESTIGATE", []cmd{
			{"programs", "[--eligible] [--new] [--changed]", "The ledger of known programs."},
			{"explain", "<id>", "The dossier — every check with its reason."},
			{"history", "<id>", "Material changes, oldest first."},
			{"replay", "<id> [--limit n]", "Read-only timeline; decisions frozen."},
			{"windows", "[--open] [--program id]", "Opportunity windows with bounded intervals."},
			{"alerts", "[--undelivered]", "Delivery ledger — sent vs pending."},
		}},
		{"ADMINISTER", []cmd{
			{"validate-config", "", "Attest the profile. 14 checks."},
			{"test-email", "[id]", "Send one rendered sample email."},
			{"version", "", "Build version, linker-stamped."},
		}},
	}
	for _, gr := range groups {
		b.WriteString(t.Section(gr.title) + "\n")
		for _, c := range gr.cmds {
			left := t.Paint(tui.FGGold, c.name)
			if c.flags != "" {
				left += " " + t.Paint(tui.FGTeal, c.flags)
			}
			b.WriteString(tui.PadRight(left, 42) +
				t.Paint(tui.FGMuted, t.Truncate(c.desc, t.Mode.Width-42)) + "\n")
		}
	}
	b.WriteString(t.Paint(tui.FGFaint, "global: --profile --state --log-level --json --no-color --quiet") + "\n")
	b.WriteString(t.Paint(tui.FGFaint, "exit 0 ok · 1 fail · 2 config · 3 degraded"))
	return b.String()
}

// ── small table helper ─────────────────────────────────────────────────────

// demoCol is a fixed-width column: header label and cell width.
type demoCol struct {
	head  string
	width int
}

// demoTableHead renders a dim letterspaced header row.
func demoTableHead(t *tui.T, cols []demoCol) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, tui.PadRight(t.Paint(tui.FGFaint, c.head), c.width))
	}
	return strings.Join(parts, "")
}
