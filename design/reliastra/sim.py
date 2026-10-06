#!/usr/bin/env python3
"""Byte-faithful simulation of internal/tui + `demo` command.

Same palette, same SGR codes, same glyphs, same width math as the Go code,
so the captured .ansi files are exactly what developers will see in their
terminal when running:  go run ./cmd/hunter demo

Usage:
    python3 sim.py            # capture all screens to screens/*.ansi
"""
import os, re, sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# ── palette (== tui.go) ──────────────────────────────────────────────────
FGText="38;2;230;234;242"; FGMuted="38;2;139;148;169"; FGFaint="38;2;74;84;104"
FGGold="38;2;232;200;122"; FGTeal="38;2;94;234;212"; FGGreen="38;2;52;211;153"
FGSky="38;2;125;211;252"; FGAmber="38;2;251;191;36"; FGRose="38;2;251;113;133"
FGViolet="38;2;167;139;250"; FGHair="38;2;110;95;60"; FGInk="38;2;8;10;16"
BOLD="1"; DIM="2"
PBGold="48;2;232;200;122"; PBGreen="48;2;52;211;153"; PBSky="48;2;125;211;252"
PBAmber="48;2;251;191;36"; PBRose="48;2;251;113;133"; PBTeal="48;2;94;234;212"
PBViolet="48;2;167;139;250"; PBGray="48;2;74;84;104"

GLYPH_U = dict(H="─",V="│",TL="┌",TR="┐",BL="└",BR="┘",Star="◈",Diamond="◆",
              Dot="●",Check="✓",Arrow="→",Mid="·",Full="█",Empty="░")
GLYPH_A = dict(H="-",V="|",TL="+",TR="+",BL="+",BR="+",Star="*",Diamond="*",
              Dot="o",Check="v",Arrow="->",Mid="-",Full="#",Empty="-")

class T:
    def __init__(self, color=True, uni=True, width=96):
        self.color, self.uni, self.w = color, uni, width
        self.g = GLYPH_U if uni else GLYPH_A
    def p(self, codes, s):
        if not self.color or not codes: return s
        return f"\x1b[{codes}m{s}\x1b[0m"
    def em(self): return "—" if self.uni else "-"
    def dot(self): return "┄" if self.uni else "."
    def trunc(self, s, w):
        if len(s) <= w: return s
        mark = "…" if self.uni else ">"
        if w <= 1: return mark
        return s[:w-1] + mark
    def rule(self): return self.p(FGFaint, self.g["H"]*self.w)
    def section(self, label):
        pad = max(2, self.w - vis(label) - 1)
        return self.p(FGFaint, label+" ") + self.p(FGHair, self.g["H"]*pad)
    def box(self, title, lines, border):
        g, w = self.g, self.w
        dashes = max(2, w - 5 - vis(title))
        out = [self.p(border, g["TL"]+g["H"]+" ") + title +
               self.p(border, " "+g["H"]*dashes+g["TR"])]
        for ln in lines:
            out.append(self.p(border, g["V"]+" ") + padr(ln, w-4) +
                       self.p(border, " "+g["V"]))
        out.append(self.p(border, g["BL"]+g["H"]*(w-2)+g["BR"]))
        return "\n".join(out)
    def pill(self, bg, fg, label):
        if not self.color: return "["+label+"]"
        return f"\x1b[{bg};{fg}m {label} \x1b[0m"
    def bar(self, frac, w, color):
        frac = min(1.0, max(0.0, frac))
        full = int(frac*w + 0.5)
        return self.p(color, self.g["Full"]*full + self.g["Empty"]*(w-full))
    def keyval(self, key, value, w):
        n = max(2, w - vis(key) - vis(value) - 2)
        return self.p(FGMuted, key) + " " + self.p(FGFaint, self.dot()*n) + " " + value
    def cells(self, cols):
        return self.p(FGFaint, " "+self.g["V"]+" ").join(cols)

def vis(s): return len(ANSI_RE.sub("", s))
def padr(s, w):
    d = w - vis(s)
    return s + " "*d if d > 0 else s

FOLD = str.maketrans({
    "─":"-","│":"|","┌":"+","┐":"+","└":"+","┘":"+","◈":"*","◆":"*",
    "●":"o","◐":"o","✓":"v","✕":"x","→":"->","·":"-","—":"-","…":">","┄":".","≠":"!="})
def fold(s): return s.translate(FOLD)

SCAN, SRC, DUR = "20261006T191500Z", "hackenproof", "38.8s"

def prompt(t, cmd):
    head, _, tail = cmd.partition(" ")
    tail = (" "+tail) if tail else ""
    return t.p(FGFaint, "$ ") + t.p(BOLD, "reliastra") + " " + t.p(FGGold, head) + t.p(FGMuted, tail)

PHASES = ["DISCOVER","FETCH","DIFF","POLICY","SCORE","ALERT","PERSIST"]
PHASE_DONE = ["324/324 · 33 pages · 4.2s","54/75 · catch-up · polite 750ms",
    "5 material · 11 minor","156 eligible · 168 rejected","priority 0-89",
    "1 armed · smtp ready","state + history + windows"]

def s_scan_live(t, fracs=(1,.72,.41,.3,.12,0,0), disc=324, elig=156, new=1, chg=4, armed=1):
    g = t.g; L = []
    title = t.p(FGGold, f"{g['Star']} RELIASTRA {t.em()} OPPORTUNITY SWEEP")
    meta = (t.p(FGMuted,"profile ")+"personal"+t.p(FGMuted," · source ")+SRC+
            t.p(FGMuted," · scan ")+SCAN+"  "+t.pill(PBGold,FGInk,"LIVE"))
    L.append(t.box(title,[meta],FGGold))
    for i,name in enumerate(PHASES):
        f = fracs[i]
        if f >= 1: detail, status = PHASE_DONE[i], t.p(FGGreen, g["Check"]+" DONE")
        elif f > 0:
            detail = f"{int(f*100+.5)}% · {PHASE_DONE[i]}"
            status = t.p(FGGold, g["Dot"]+" LIVE")
        else: detail, status = "queued", t.p(FGFaint, "QUEUED")
        L.append("  "+padr(t.p(BOLD,name),9)+"  "+t.bar(f,16,FGGold)+" "+
                 padr(t.p(FGMuted,t.trunc(detail,52)),52)+padr(status,14))
    L.append(t.section("LIVE COUNTERS"))
    cell = lambda l,v,c: padr(t.p(FGMuted,l+" ")+t.p(c,v),20)
    L.append(t.box(t.p(FGFaint,"COUNTERS"),[t.cells([
        cell("DISCOVERED",str(disc),FGSky), cell("ELIGIBLE",str(elig),FGGreen),
        cell("NEW·CHG",f"{new}·{chg}",FGGold), cell("ARMED",str(armed),FGGold)])],FGFaint))
    L.append(t.p(FGFaint, f"{g['Dot']} polite 750ms {g['Mid']} 4 workers {g['Mid']} "
        f"esc aborts cleanly {t.em()} state is never half-written"))
    return "\n".join(L)

def thead(t, cols):
    return "".join(padr(t.p(FGFaint,h),w) for h,w in cols)

def s_scan_report(t):
    g=t.g; L=[]
    L.append(t.box(t.p(FGGold,f"{g['Star']} VERDICT"),[
        t.p(FGGold+";"+BOLD, f"{g['Diamond']} 1 ACTIONABLE OPPORTUNITY"),
        "delivered "+t.p(BOLD,"1/1")+t.p(FGMuted," · suppressed 0 · errors 0 · exit ")+
        t.p(BOLD,"0")+t.p(FGMuted," · coverage ")+t.p(FGGreen+";"+BOLD,"100% TRUSTED"),
        f"scan {SCAN}"+t.p(FGMuted,f" · {DUR} · source {SRC}")],FGGold))
    cell = lambda l,v,c: padr(t.p(FGMuted,l+" ")+t.p(c,v),20)
    L.append(t.box(t.p(FGFaint,"SWEEP"),[t.cells([
        cell("EVALUATED","324",FGSky),cell("ELIGIBLE","156",FGGreen),
        cell("NEW·CHG·MIN","1·4·11",FGGold),cell("ERRORS","0",FGText)])],FGFaint))
    L.append(t.section(f"COVERAGE {t.em()} DID THIS SWEEP SEE THE PLATFORM?"))
    L.append(t.p(FGGreen+";"+BOLD,f"{g['Dot']} 100.0%")+" "+t.bar(1,38,FGGreen)+"  "+
            t.p(FGMuted,"324/324 · floor 90% · absent 0 · departed 2"))
    L.append(t.section("ALERT DISPATCHED"))
    L.append(t.box(t.pill(PBGold,FGInk,"NEW MATCH")+" "+
        t.p(FGMuted,"PRIO 87/100 · $500 CEILING"),[
        t.p(BOLD,"Swisstronik Blockchain Stability"),
        t.p(FGMuted,"launched 3y ago · detected <1m · 4 submissions · low competition"),
        t.p(FGSky,"web2 · web_application · 6 in-scope assets"),
        t.p(FGMuted,"why: no reputation gate · no fee · no KYC · crypto_platform"),
        t.pill(PBGreen,FGInk,"SENT")+"  "+
        t.p(FGTeal,"hackenproof.com/programs/swisstronik-blockchain-stability")],FGGold))
    L.append(t.section("ELIGIBLE · TOP 5 BY ATTENTION PRIORITY"))
    L.append(thead(t,[("PROGRAM",36),("SCORE",14),("AGE",6),("TOP REASON",40)]))
    for name,sc,age,reason in [
        ("Ternoa Web and Apps",89,"4y","ceiling $50,000 · 10 assets"),
        ("Sweed Web",88,"1y","23 in-scope assets · infra+web"),
        ("Avalanche Websites and APIs",87,"5y","api · web · $10k ceiling"),
        ("Swisstronik Blockchain Stability",87,"3y","4 submissions · low competition"),
        ("1inch Business",84,"1y","api.1inch.com · SaaS platform")]:
        L.append(padr(t.p(FGGold,g["Diamond"])+" "+name,36)+
            padr(t.bar(sc/100,8,FGGold)+" "+t.p(FGGold+";"+BOLD,str(sc)),14)+
            padr(t.p(FGMuted,age),6)+t.p(FGMuted,t.trunc(reason,40)))
    L.append(t.p(FGFaint,f"+ 151 more eligible · reliastra programs --eligible · machine-readable: --json"))
    return "\n".join(L)

def s_programs(t):
    L=[t.box(t.p(FGGold,"◈ PROGRAM LEDGER"),
        [t.p(FGMuted,f"profile personal · 156 eligible of 324 known · scan {SCAN}")],FGGold)]
    L.append(thead(t,[("PROGRAM",36),("STATE",13),("SCORE",7),("LAUNCH/SEE",12),("SURFACES",28)]))
    for name,sub,pill,sc,ages,surf in [
        ("1inch Business","up to $100,000 · 163 reports",t.pill(PBGreen,FGInk,"LIVE"),84,"1y / 3d","api · web_app"),
        ("Aurora Web","up to $100,000 · 124 reports",t.pill(PBGreen,FGInk,"LIVE"),82,"3y / 3d","web2 · web_app"),
        ("Ult: Trade Stocks & Crypto","up to $20,000 · 74 reports",t.pill(PBGold,FGInk,"NEW"),81,"8d / 3d","api · mobile"),
        ("WEEX Web & App","up to $10,000 · 379 reports",t.pill(PBGreen,FGInk,"LIVE"),79,"1y / 3d","web_app · mobile"),
        ("WhiteBIT","up to $10,000 · 297 reports",t.pill(PBGreen,FGInk,"LIVE"),78,"5y / 3d","api · web_app"),
        ("Astros Web","up to $5,000 · 58 reports",t.pill(PBSky,FGInk,"SCOPE+"),76,"11m / 3d","web_app")]:
        L.append(padr(t.p(BOLD,t.trunc(name,36)),36)+padr(pill,13)+
            padr(t.p(FGGold+";"+BOLD,str(sc)),7)+padr(t.p(FGMuted,ages),12)+
            t.p(FGSky,t.trunc(surf,28)))
        L.append(t.p(FGFaint,"  "+sub))
    L.append(t.p(FGFaint,"6 of 156 shown · reliastra explain <id> opens the dossier"))
    return "\n".join(L)

def s_explain(t):
    g=t.g; L=[]
    L.append(t.box(t.p(FGGreen,f"{g['Check']} DOSSIER · 1INCH BUSINESS"),[
        t.p(FGGreen+";"+BOLD,"ELIGIBLE")+t.p(FGMuted," · hackenproof · state live · confidence high"),
        t.p(FGMuted,"priority ")+t.p(FGGold+";"+BOLD,"84/100")+
        t.p(FGMuted," · bounty $100,000 · paid $34,200 · 163 reports"),
        t.p(FGTeal,"hackenproof.com/programs/1inch-business")],FGGreen))
    L.append(t.section(f"ACCESS {t.em()} CAN YOU REACH IT?"))
    ok=t.p(FGGreen,g["Check"]+" ")
    for k,v in [("reputation",ok+"none required (<= 80 allowed)"),("submission fee",ok+"none"),
        ("kyc",ok+"not required"),("proof of concept",ok+"accepted"),
        ("paid to date","$34,200 · 163 reports")]:
        L.append(t.keyval(k,v,t.w))
    L.append(t.section(f"ATTACK SURFACE {t.em()} 4 TARGETS"))
    L.append(t.p(FGSky,"api · web2 · web_application")+t.p(FGMuted," · capabilities: auth · accounts · trading"))
    L.append(t.p(FGGreen,"+ [api]")+" api.1inch.com")
    L.append(t.p(FGGreen,"+ [web]")+" business.1inch.com + /portal + /portal/documentation")
    L.append(t.section(f"CRYPTO {t.em()} PLATFORM, NOT PROTOCOL"))
    L.append(t.keyval("kind",t.p(FGTeal+";"+BOLD,"crypto_platform")+t.p(FGMuted," · ordinary software work"),t.w))
    L.append(t.keyval("traits",t.p(FGSky,"crypto_api · crypto_platform · crypto_web_application"),t.w))
    L.append(t.keyval("dominance veto",t.p(FGGreen,f"{g['Check']} no excluded traits · 0% < 60% threshold"),t.w))
    L.append(t.section(f"POLICY CHECKS {t.em()} EXPLAINED"))
    P, I = t.pill(PBGreen,FGInk,"PASS"), t.pill(PBSky,FGInk,"INFO")
    for chip,id_,reason in [(P,"access.reputation","no reputation required (<= 80 allowed)"),
        (P,"access.kyc","KYC not required"),(P,"state.allowed","live in {live, new}"),
        (P,"surface.match","exposes api, web2, web_application"),
        (P,"crypto.allow","carries crypto_platform + crypto_api"),
        (I,"timing.launch","launched 1y ago · change window still evaluable")]:
        L.append(chip+" "+padr(t.p(BOLD,id_),20)+t.p(FGMuted,t.trunc(reason,t.w-6-1-20-1)))
    L.append(t.section(f"ATTENTION PRIORITY {t.em()} ORDERING AID"))
    for name,val,basis in [("freshness",100,"first seen just now"),
        ("surface relevance",100,"matches api, web2, web_application"),
        ("eligibility",90,"9 of 10 requirements satisfied"),("bounty",85,"ceiling $100,000"),
        ("low competition",46,"163 submissions reported")]:
        L.append(padr(t.p(FGMuted,name),19)+padr(t.p(FGGold+";"+BOLD,str(val)),4)+
            t.bar(val/100,28,FGTeal if val>=90 else FGGold)+" "+
            t.p(FGFaint,t.trunc(basis,t.w-19-4-28-1)))
    fp = lambda h: t.trunc(h,9)
    L.append(t.p(FGFaint,f"fingerprints scope {fp('57faf179357085ac')} · requirements {fp('4c6caf74c89214cb')} · metadata {fp('50a06a5186b73588')}"))
    return "\n".join(L)

def s_windows(t):
    g=t.g
    w1=[t.p(FGMuted,"observed ")+t.p(FGGold+";"+BOLD,"between 42m and 47m ago")+
        t.p(FGMuted,f" · opened by scan {SCAN}"),
        t.p(FGMuted,"triggers ")+t.pill(PBSky,FGInk,"SCOPE_EXPANSION")+" "+t.pill(PBTeal,FGInk,"TARGET_ADDED"),
        t.p(FGTeal,g["Diamond"])+" + api.astros.ag entered scope "+t.p(FGMuted,"[api]"),
        t.p(FGTeal,g["Diamond"])+f" reward ceiling $3,000 "+t.p(FGGold,g["Arrow"])+" $5,000",
        t.p(FGMuted,"submissions baseline 58 · current 58 · ")+t.p(FGGreen+";"+BOLD,f"+0 {t.em()} uncrowded")]
    w2=[t.p(FGMuted,"observed ")+t.p(FGGold+";"+BOLD,"between 3h and 3h 05m ago")+
        t.p(FGMuted," · launch-gated, source-reported"),
        t.p(FGMuted,"triggers ")+t.pill(PBGold,FGInk,"NEW_PROGRAM")+" "+t.pill(PBTeal,FGInk,"NEWLY_ELIGIBLE"),
        t.p(FGTeal,g["Diamond"])+" first observed on listing page 1 · status NEW",
        t.p(FGTeal,g["Diamond"])+" access resolved: no gates · KYC for payout only",
        t.p(FGMuted,"submissions baseline 70 · current 74 · ")+t.p(FGAmber+";"+BOLD,f"+4 {t.em()} warming")]
    return "\n".join([
        t.box(t.p(FGGold,f"◐ OPEN · ASTROS WEB {t.em()} SCOPE EXPANSION"),w1,FGGold),
        t.box(t.p(FGGold,f"◐ OPEN · ULT: TRADE STOCKS & CRYPTO {t.em()} NEWLY ELIGIBLE"),w2,FGGold),
        t.p(FGFaint,"2 open · closed windows stay queryable · reliastra replay <id> renders the timeline")])

def s_alerts(t):
    L=[t.box(t.p(FGGold,"◈ DELIVERY LEDGER · 5 OF 6 DELIVERED · SMTP READY"),
        [t.p(FGMuted,"every alert recorded · deduplicated by fingerprint · never announced twice")],FGGold)]
    L.append(thead(t,[("WHEN (UTC)",17),("KIND",15),("STATUS",10),("PRIO",6),("SUBJECT",48)]))
    rows=[("10-06 19:15:38",t.pill(PBGold,FGInk,"NEW MATCH"),t.pill(PBGreen,FGInk,"SENT"),87,"Swisstronik Blockchain Stability — Web — <1m"),
        ("10-03 19:25:58",t.pill(PBGold,FGInk,"NEW MATCH"),t.pill(PBGreen,FGInk,"SENT"),88,"Sweed Web — infra+web · 23 assets"),
        ("10-03 19:13:15",t.pill(PBSky,FGInk,"SCOPE +"),t.pill(PBGreen,FGInk,"SENT"),86,"Astros Web — target added: api.astros.ag"),
        ("10-03 19:12:40",t.pill(PBGold,FGInk,"NEW MATCH"),t.pill(PBGreen,FGInk,"SENT"),89,"Ternoa Web and Apps — $50k ceiling"),
        ("10-02 21:48:40",t.pill(PBSky,FGInk,"SCOPE +"),t.pill(PBGreen,FGInk,"SENT"),84,"1inch Business — portal docs in scope"),
        ("10-02 21:44:39",t.pill(PBViolet,FGInk,"RE-ACTIVATED"),t.pill(PBAmber,FGInk,"RETRY 2"),72,"Zest Protocol — listing republished")]
    for when,kind,status,prio,subj in rows:
        if not t.uni: subj = subj.replace("—","-")
        L.append(padr(t.p(FGMuted,when),17)+padr(kind,15)+padr(status,10)+
            padr(t.p(FGGold+";"+BOLD,str(prio)),6)+t.trunc(subj,48))
    L.append(t.p(FGAmber,f"last error: 421 smtp busy {t.em()} next attempt in 5m"))
    L.append(t.p(FGFaint,"reliastra alerts --undelivered isolates pending"))
    return "\n".join(L)

def s_validate(t):
    g=t.g; L=[]
    L.append(t.box(t.p(FGGreen,f"{g['Star']} PROFILE ATTESTED {t.em()} PERSONAL"),
        [t.p(FGGreen+";"+BOLD,"VALID")+t.p(FGMuted," · configs/profiles/personal.yaml · 14/14 thresholds verified · exit 0")],FGGreen))
    L.append(t.section("ATTESTATION"))
    P=t.pill(PBGreen,FGInk,"PASS")
    for c in ["sources · hackenproof enabled","access gates · rep <= 80 · fee <= $5 · no KYC",
        "crypto mode auto · 8 allowed · 5 excluded · veto >= 60%",
        "coverage floor 90% · grace 2 sweeps","windows · new 24h · change 72h · max age 168h"]:
        L.append(P+" "+t.p(FGMuted,c))
    L.append(t.section("PROFILE LEDGER"))
    for k,v in [("target domains","7 included"),("accepted states","live · new"),
        ("min alert severity",t.p(FGAmber,"medium")),
        ("require eligible",t.p(FGGreen,f"{g['Check']} hard gate")),
        ("notifications",t.p(FGGreen,f"{g['Check']} enabled · cap 10/scan")),
        ("pacing","750ms · 4 workers · 45s timeout")]:
        L.append(t.keyval(k,v,t.w))
    L.append(t.p(FGFaint,"the coverage floor is printed here so exit 3 is always traceable"))
    return "\n".join(L)

def s_help(t):
    L=[t.box(t.p(FGGold,"◈ RELIASTRA · SIGNAL OVER NOISE · V2.0.0"),
        [t.p(FGMuted,"hunter engine inside · zero-deps binary · --json stays byte-stable")],FGGold)]
    for title,cmds in [
        ("OPERATE",[("scan","[--dry-run] [--no-details]","Discover, evaluate, alert in one pass."),
                    ("sync","","Alias for scan — the manual-run spelling.")]),
        ("INVESTIGATE",[("programs","[--eligible] [--new] [--changed]","The ledger of known programs."),
            ("explain","<id>","The dossier — every check with its reason."),
            ("history","<id>","Material changes, oldest first."),
            ("replay","<id> [--limit n]","Read-only timeline; decisions frozen."),
            ("windows","[--open] [--program id]","Opportunity windows with bounded intervals."),
            ("alerts","[--undelivered]","Delivery ledger — sent vs pending.")]),
        ("ADMINISTER",[("validate-config","","Attest the profile. 14 checks."),
            ("test-email","[id]","Send one rendered sample email."),
            ("version","","Build version, linker-stamped.")])]:
        L.append(t.section(title))
        for name,flags,desc in cmds:
            left=t.p(FGGold,name)+((" "+t.p(FGTeal,flags)) if flags else "")
            L.append(padr(left,42)+t.p(FGMuted,t.trunc(desc,t.w-42)))
    L.append(t.p(FGFaint,"global: --profile --state --log-level --json --no-color --quiet"))
    L.append(t.p(FGFaint,"exit 0 ok · 1 fail · 2 config · 3 degraded"))
    return "\n".join(L)

SCREENS=[("scan-live","scan --profile personal",s_scan_live),
    ("scan-report","scan",s_scan_report),("programs","programs --eligible --limit 6",s_programs),
    ("explain","explain 1inch-business",s_explain),("windows","windows --open",s_windows),
    ("alerts","alerts --limit 6",s_alerts),("validate","validate-config",s_validate),
    ("help","help",s_help)]

def main():
    outdir=os.path.join(os.path.dirname(os.path.abspath(__file__)),"screens")
    os.makedirs(outdir,exist_ok=True)
    t=T(); fails=[]
    for name,cmd,fn in SCREENS:
        text=prompt(t,cmd)+"\n"+fn(t)+"\n"
        for i,ln in enumerate(text.split("\n")):
            v=vis(ln)
            if v>96: fails.append(f"{name}:{i+1} width {v}: {ln[:60]}")
        open(os.path.join(outdir,name+".ansi"),"w").write(text)
        print(f"captured {name}.ansi  ({len(text.splitlines())} lines)")
    # degradation proof: no-color + ascii variant of the richest screen
    tp=T(color=False,uni=False)
    plain = fold(prompt(tp,"scan")+"\n"+s_scan_report(tp)+"\n")
    assert all(ord(c) < 128 or c in "\n" for c in plain), "non-ASCII leaked into plain capture"
    open(os.path.join(outdir,"scan-report.plain.ansi"),"w").write(plain)
    print("captured scan-report.plain.ansi (NO_COLOR + ASCII)")
    if fails:
        print("\nWIDTH VIOLATIONS:"); print("\n".join(fails)); sys.exit(1)
    print("\nOK — every line within 96 columns.")

if __name__=="__main__": main()
