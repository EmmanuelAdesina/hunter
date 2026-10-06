# ◈ Reliastra CLI — Enterprise Design Spec (Obsidian Executive)

> **Status:** PRE-DEVELOPMENT DEMO — no engine code changed.
> **Demo:** open `design/reliastra/index.html` (zero build step, works from `file://`).
> **Engine:** the `hunter` pipeline stays untouched — discover → diff → policy → score → alert. This spec only re-cuts the **render layer**.

---

## 1. Brand

| Token | Value |
|---|---|
| Name | **Reliastra** — *Opportunity Intelligence* |
| CLI | `reliastra` (verb-first: `scan`, `explain`, `windows`) |
| Tagline | *Signal over noise.* |
| Mark | Eight-pointed **Astra star** in a hairline orbit ring. Star = signal found. Ring = the sweep that never stops. |
| Voice | Calm, precise, accountable. Never cute. Never loud unless there is an opportunity. |

### Why "not generic"

Generic CLIs print tables and exit. Reliastra renders **verdicts**:

1. **Verdict first** — a gold/emerald banner answers *"is there anything worth my evening?"* in <1s.
2. **Trust is rendered** — coverage (observed/expected, floor marker, absent programs) is on *every* scan screen, not hidden in `--verbose`.
3. **Evidence unfolds** — alert cards → top-10 table → full ledger. Each layer earns the next scroll.
4. **Time is honest** — launch age and seen age are always separate; window intervals are always bounded (*"between 42m and 47m ago"*), never fake point-times.

---

## 2. Theme — Obsidian Executive

Dark-luxe operations-floor aesthetic. Deep void canvas, champagne-gold signal color, hairline borders, tabular numerals.

### Palette

| Role | Name | Hex | ANSI | Used for |
|---|---|---|---|---|
| Brand / opportunity | Astra Gold | `#E8C87A` | `38;2;232;200;122` | verdicts, NEW, scores, primary actions |
| Evidence / links | Signal Teal | `#5EEAD4` | `38;2;94;234;212` | targets, hints, next-actions |
| Go / trusted | Emerald | `#34D399` | `38;2;52;211;153` | ELIGIBLE, DELIVERED, coverage fill |
| Change / intel | Sky | `#7DD3FC` | `38;2;125;211;252` | CHANGED, surface tags |
| Caution | Amber | `#FBBF24` | `38;2;251;191;36` | PENDING, coverage floor, retry |
| Critical | Rose | `#FB7185` | `38;2;251;113;133` | DEGRADED, FAIL, veto |
| Canvas | Obsidian | `#05070D` | — | terminal background |
| Surface | Slate | `#0B111E` | — | cards, bands |
| Text / muted / faint | — | `#E6EAF2` / `#8B94A9` / `#4A5468` | — | hierarchy |

Full tokens: `theme.json`.

### Typography (terminal)

- **Mono only** in terminal output: JetBrains Mono → SF Mono → Cascadia → Menlo.
- 12.5px/1.75 body, 11px micro-labels with `0.2em` tracking, tabular numerals for all counts.
- Symbols: `◈ ◆ ● ◐ ❚❚ ✓ ✉ ▦ ◌` — all in the safe box-drawing + geometric set. **ASCII fallback** (`*`, `+`, `-`, `ok`) when `TERM=dumb` or `NO_COLOR`.

---

## 3. Screen designs (see live demo)

### 01 — `reliastra scan` (live)
Cinematic phased run for the human operator:
- **Header band**: mark + profile + source + scan id + LIVE pill.
- **Phase rail**: 7 phases (discover → persist) with progress bars and `✓ DONE / ◌ ACTIVE / … QUEUED` states.
- **Live counters**: discovered / eligible / new·changed / alerts-armed metric cards.
- Footer: pacing + worker facts, `esc aborts cleanly — state is never half-written`.

### 02 — `reliastra scan` (verdict report)
- **Verdict banner** (gold when opportunity, emerald when quiet-but-trusted, rose when degraded): counts + delivery + coverage + exit code.
- **Metric cards**, **coverage gauge with floor marker** (the trust instrument), **alert card with priority ring + bounty**, **top-5 eligible table with score micro-bars**.
- One-line next actions (`programs --eligible`, `--json`).

### 03 — `reliastra programs`
The **ledger**: program + bounty/competition subline, state pills (`● LIVE`, `◆ NEW`, `◐ SCOPE+`, `❚❚ PAUSED`), gold scores, separated LAUNCHED/SEEN columns, sky surface tags.

### 04 — `reliastra explain <id>`
The **dossier**: verdict band → access grid → surface map → crypto strip (platform-vs-protocol verdict + dominance veto math) → policy checks (`PASS/FAIL/INFO` chips with reasons) → priority ledger with bars.

### 05 — `reliastra windows --open`
**Window cards**: status pill, bounded observed interval, trigger pills, atomic `◆` delta evidence, submission movement with crowd verdict (*+0 uncrowded / +4 warming*).

### 06 — `reliastra alerts`
**Delivery ledger**: UTC time, kind pills (`NEW MATCH`, `SCOPE +`, `RE-ACTIVATED`), status pills (`✓ SENT`, `◌ RETRY n`), priority, subject. Retry rows name the last error and next attempt.

### 07 — `reliastra validate-config`
**Attestation**: `PROFILE ATTESTED` banner + check chips + two-column profile ledger. The coverage floor is printed here so exit-3 is always traceable.

### 08 — `reliastra help`
**Command atlas** grouped OPERATE / INVESTIGATE / ADMINISTER, with global flags and exit codes in one footer line.

---

## 4. Engineering contract (enterprise constraints)

1. **Zero new dependencies.** Theme engine = `internal/tui/theme.go`, stdlib ANSI only. The repo's `go.mod` stays at one YAML lib.
2. **TTY-gated.** Obsidian renders on TTY; piped/CI output degrades to `plain` (current format, byte-stable) unless `--theme obsidian` is forced.
3. **`--json` untouched.** Machine output never carries styling, ever.
4. **`NO_COLOR` + `--no-color` + `--quiet`** respected everywhere. `--quiet` prints only the verdict line + errors.
5. **Render-only.** No policy/pipeline/scoring change. Files touched: `internal/cli/*.go` render funcs + new `internal/tui/`.
6. **Never color-alone.** Every color pairs with a text label/pill so red-green vision and monochrome logs stay legible.
7. **Exit codes frozen:** `0` ok · `1` fail · `2` bad config · `3` degraded.
8. **Golden tests.** Each screen in the HTML demo becomes a golden file (`testdata/*.golden`) with ANSI stripped + preserved variants.

### Proposed file layout

```
internal/tui/
  theme.go      # tokens, ANSI codes, NO_COLOR/dumb detection, width handling
  components.go # band, verdict, pills, bars, tables, cards (writer-based, testable)
  scan.go       # live rail + verdict report composers
internal/cli/
  *_render.go   # per-command composers move here out of query.go/scan.go (pure moves)
```

### Rollout (behind a flag)

1. `--theme obsidian|plain` (default: auto → obsidian on TTY, plain otherwise).
2. Ship `scan` report first → `programs` → `explain` → `windows`/`alerts` → `help`/`validate`.
3. Each step: golden test + demo HTML updated. CI asserts plain output is byte-identical to today.

---

## 5. CLI image (container)

- Base: `gcr.io/distroless/static-debian12` (non-root, no shell).
- Binary: `reliastra` (CGO off, `-trimpath`, version linker-stamped).
- Labels: `org.opencontainers.image.*`, plus `reliastra.theme=obsidian`.
- Entrypoint: `["/reliastra"]`, default CMD `["scan"]`; config mounted at `/etc/reliastra/profile.yaml`, state at `/var/lib/reliastra`.
- Plain theme forced when stdout is not a TTY (already the auto behavior), so container logs stay greppable.

---

## 6. Approvals requested

- [ ] Brand: name **Reliastra**, mark, tagline.
- [ ] Theme: Obsidian Executive palette + verdict-first layout.
- [ ] Screen priority order for build (proposed: scan → programs → explain → rest).
- [ ] Binary rename `hunter` → `reliastra` (with `hunter` kept as alias for one release), or keep `hunter` binary with Reliastra skin?

---

## 7. Working prototype (this branch)

The theme is no longer just a mockup — it runs:

- `internal/tui/tui.go` — theme engine (palette, glyphs, box/pill/bar/table/keyval primitives, stdlib only).
- `internal/tui/fold.go` — ASCII fold for `--ascii` / dumb terminals.
- `internal/cli/demo.go` — `demo` command rendering all 8 screens with fixed mock evidence.
- `design/reliastra/preview.html` — byte-exact captures of the real renderer output (view in browser).
- `design/reliastra/screens/*.ansi` + `sim.py` + `ansi2html.py` — capture/regeneration toolchain.

```bash
go run ./cmd/hunter demo --screen scan-report
go run ./cmd/hunter demo --animate
go run ./cmd/hunter demo --screen scan-report --no-color --ascii
```
