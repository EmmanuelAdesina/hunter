#!/usr/bin/env python3
"""Convert captured .ansi screens to preview.html — byte-exact content,
SGR colors mapped 1:1 to CSS. No restyling of the terminal output itself."""
import html, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
SGR = re.compile(r"\x1b\[([0-9;]*)m")

def style_for(fg=None, bg=None, bold=False, dim=False):
    css = []
    if fg: css.append(f"color:rgb({fg[0]},{fg[1]},{fg[2]})")
    if bg: css.append(f"background:rgb({bg[0]},{bg[1]},{bg[2]});border-radius:3px")
    if bold: css.append("font-weight:700")
    if dim: css.append("opacity:.55")
    return ";".join(css)

def ansi_to_html(text):
    out, fg, bg, bold, dim, open_span = [], None, None, False, False, False
    def close():
        nonlocal open_span
        if open_span:
            out.append("</span>"); open_span = False
    pos = 0
    for m in SGR.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        params = m.group(1)
        if params in ("", "0"):
            close(); fg, bg, bold, dim = None, None, False, False
            continue
        nums = [int(x) if x else 0 for x in params.split(";")]
        i = 0
        while i < len(nums):
            n = nums[i]
            if n == 0: close(); fg,bg,bold,dim = None,None,False,False
            elif n == 1: bold = True
            elif n == 2: dim = True
            elif n == 38 and i+4 < len(nums) and nums[i+1] == 2:
                fg = tuple(nums[i+2:i+5]); i += 4
            elif n == 48 and i+4 < len(nums) and nums[i+1] == 2:
                bg = tuple(nums[i+2:i+5]); i += 4
            i += 1
        close()
        st = style_for(fg, bg, bold, dim)
        if st:
            out.append(f'<span style="{st}">'); open_span = True
    out.append(html.escape(text[pos:]))
    close()
    return "".join(out)

SCREENS = [
    ("scan-live", "01 · scan — live operation", "reliastra scan --profile personal"),
    ("scan-report", "02 · scan — verdict report", "reliastra scan"),
    ("programs", "03 · programs — the ledger", "reliastra programs --eligible --limit 6"),
    ("explain", "04 · explain — the dossier", "reliastra explain 1inch-business"),
    ("windows", "05 · windows — open research windows", "reliastra windows --open"),
    ("alerts", "06 · alerts — delivery ledger", "reliastra alerts --limit 6"),
    ("validate", "07 · validate-config — attestation", "reliastra validate-config"),
    ("help", "08 · help — command atlas", "reliastra help"),
    ("scan-report.plain", "09 · degradation proof — NO_COLOR + ASCII", "reliastra scan (TERM=dumb)"),
]

def main():
    blocks = []
    for name, title, cmd in SCREENS:
        raw = open(os.path.join(HERE, "screens", name + ".ansi")).read().rstrip("\n")
        body = ansi_to_html(raw)
        blocks.append(
            f'<section id="{name}"><div class="shead"><span class="stitle">{title}</span>'
            f'<code>{html.escape(cmd)}</code></div><pre>{body}</pre></section>')
    nav = "".join(f'<a href="#{n}">{t.split("·")[0].strip()}</a>' for n, t, _ in SCREENS)
    page = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reliastra CLI — Exact Terminal Captures · Obsidian Executive</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--gold:#E8C87A;--muted:#8B94A9;--faint:#4A5468}
*{margin:0;padding:0;box-sizing:border-box}
body{background:#04060B;color:#E8ECF4;font-family:Inter,system-ui,sans-serif;padding:0 0 80px}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
header{padding:52px 0 10px}
.eyebrow{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.3em;color:var(--gold);margin-bottom:14px}
h1{font-size:clamp(28px,4vw,44px);font-weight:800;letter-spacing:-.02em}
h1 em{font-style:normal;color:var(--gold)}
.sub{color:var(--muted);margin-top:12px;line-height:1.7;max-width:760px;font-size:14.5px}
.sub code,.run code{font-family:'JetBrains Mono',monospace;font-size:12px;color:#5EEAD4;background:rgba(94,234,212,.08);padding:1px 7px;border-radius:6px}
.run{margin:22px 0 6px;border:1px solid rgba(232,200,122,.2);border-radius:12px;padding:16px 20px;background:rgba(232,200,122,.04);font-family:'JetBrains Mono',monospace;font-size:12.5px;line-height:2}
.run .c{color:var(--faint)}
nav{position:sticky;top:0;z-index:5;display:flex;gap:8px;flex-wrap:wrap;padding:14px 0;background:rgba(4,6,11,.92);backdrop-filter:blur(10px);border-bottom:1px solid rgba(232,200,122,.12);margin-top:18px}
nav a{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;border:1px solid rgba(139,148,169,.25);border-radius:8px;padding:6px 11px}
nav a:hover{color:var(--gold);border-color:rgba(232,200,122,.4)}
section{margin-top:34px}
.shead{display:flex;align-items:center;gap:14px;margin-bottom:10px;flex-wrap:wrap}
.stitle{font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:.14em;color:var(--gold);font-weight:700}
.shead code{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--muted)}
pre{background:#05070D;border:1px solid rgba(232,200,122,.16);border-radius:14px;padding:22px 24px;font-family:'JetBrains Mono','SF Mono',Menlo,monospace;font-size:12.3px;line-height:1.72;overflow-x:auto;color:#E6EAF2;box-shadow:0 24px 60px rgba(0,0,0,.5)}
footer{margin-top:44px;color:var(--faint);font-family:'JetBrains Mono',monospace;font-size:11px;line-height:2}
footer b{color:var(--gold)}
</style></head>
<body><div class="wrap">
<header>
<div class="eyebrow">RELIASTRA CLI · OBSIDIAN EXECUTIVE · TERMINAL UI</div>
<h1>Exactly what developers <em>see in their terminal.</em></h1>
<p class="sub">Every block below is a <b>byte-exact capture</b> of the real renderer output — same SGR codes, same
glyphs, same 96-column math as <code>internal/tui</code> + the <code>demo</code> command. Nothing is mocked in HTML.
Screen 09 proves the degradation path: with <code>NO_COLOR</code> / <code>TERM=dumb</code> / <code>--ascii</code>,
output is pure 7-bit ASCII — pills become <code>[LABELS]</code>, boxes become <code>+--+</code>.</p>
<div class="run">
<span class="c"># run the real thing (Go 1.26+, zero new deps):</span><br>
go run ./cmd/hunter demo <span class="c"># all 8 screens</span><br>
go run ./cmd/hunter demo --screen scan-report<br>
go run ./cmd/hunter demo --animate <span class="c"># replay the live phase rail</span><br>
go run ./cmd/hunter demo --screen scan-report --no-color --ascii <span class="c"># screen 09</span>
</div>
</header>
<nav>NAV</nav>
BLOCKS
<footer>◈ RELIASTRA · <b>internal/tui/tui.go</b> (theme engine) + <b>internal/tui/fold.go</b> (ASCII fold) + <b>internal/cli/demo.go</b> (8 screens) · stdlib only · --json untouched · exit codes frozen<br>
captures: design/reliastra/screens/*.ansi · regenerate: python3 sim.py && python3 ansi2html.py</footer>
</div></body></html>"""
    page = page.replace("NAV", nav).replace("BLOCKS", "\n".join(blocks))
    open(os.path.join(HERE, "preview.html"), "w").write(page)
    print(f"preview.html written ({len(blocks)} screens)")

if __name__ == "__main__":
    main()
