# hunter

A personal bug-bounty opportunity monitor.

It watches bug-bounty programs, decides whether newly launched programs and
material changes are actually reachable and worth your time, and emails you only
when a configured trigger has fresh evidence. Launch age and change age are
separate clocks: a five-year-old program can still be worth a look when its scope
or access gates changed recently.

The goal is not a dashboard. The goal is to **see the right opportunity before
you spend an evening reading through everything else**.

```
$ hunter scan
scan_id=20261002T215638Z source=hackenproof discovered=324 evaluated=324
listing_only=324 new=1 changed=4 eligible=156 rejected=168 alerts=1
sent=1 failed=0 errors=0 duration=38.8s
```

---

## What it does

Every five minutes it:

1. **Discovers** every program a platform publishes.
2. **Reads the detail record** only where something may have changed.
3. **Normalizes** the source's own vocabulary into a stable internal model.
4. **Compares** against what it last saw, using content fingerprints.
5. **Evaluates** each program against your profile, explaining every decision.
6. **Prioritizes** what deserves attention, publishing each component.
7. **Alerts** once, with a message you can act on from a phone.
8. **Records** the result so the same thing is never announced twice.
9. **Tracks opportunity windows** with their individual deltas and the source's
   submission-count movement since each transition.

A new-program alert is gated by the source-reported launch date. A change alert is
gated by the interval between the last detail observation that did not show the
change and the first one that did. If Hunter cannot bound a change in time, it
does not call that change recent and does not alert on it.

---

## The crypto distinction

This is the distinction the whole thing turns on.

A crypto **exchange with a web application and an API** is ordinary software
work: authentication, sessions, business logic, payment flows, authorization. A
**smart-contract or consensus protocol** program is a different discipline
entirely.

Treating "it's crypto" as one bucket is the fastest way to make an alert channel
useless. Hunter classifies crypto programs into traits and lets the profile decide
what to do with them:

```yaml
crypto:
  enabled: true
  mode: auto                    # auto | off | only | platform_only
  require_allowed_trait: true
  allowed:                      # makes a crypto program relevant
    - crypto_platform
    - exchange
    - crypto_api
    - crypto_backend
    # ...
  excluded:                     # vetoes a program when these dominate
    - smart_contract_only
    - solidity_only
    - protocol_consensus
    # ...
  dominance_ratio: 0.6
```

`dominance_ratio` is what keeps it honest. A crypto exchange that happens to list
one contract is **not** excluded, because its platform character dominates. A
staking protocol that mentions an API is **not** admitted, because it does not
have platform character. Only when excluded traits reach the configured share of
a program's traits does the veto apply.

Classification reads structured evidence for traits — asset kinds, the source's
own labels, scope titles — and reserves free prose for deciding *whether a program
is crypto at all*. That separation is deliberate: marketing copy full of "web3"
must not promote a smart-contract program into a platform.

---

## Install

Requires Go 1.26 or newer. No other dependency: one pure-Go YAML library, and
nothing else.

```bash
git clone <this repository> hunter && cd hunter
make build          # -> bin/hunter
```

Or build directly:

```bash
go build -o bin/hunter ./cmd/hunter
```

---

## Try it

```bash
# Validate the profile. Every policy threshold is checked before anything else.
bin/hunter validate-config

# Re-parse recorded upstream pages. No network required.
bin/hunter test-fixtures

# One live scan, generating and recording alerts but sending no email.
bin/hunter scan --dry-run

# One live scan that can send email.
export EMAIL_SMTP_HOST=smtp.example.com EMAIL_SMTP_PORT=587 \
       EMAIL_USERNAME=you@example.com EMAIL_PASSWORD=... \
       ALERT_RECIPIENT=you@example.com
bin/hunter scan
```

---

## Commands

| Command | Purpose |
|---|---|
| `hunter scan` | Discover, evaluate, and alert in one pass. |
| `hunter scan --full` | Traverse the whole listing rather than a page budget. |
| `hunter scan --dry-run` | Generate and record alerts without sending. |
| `hunter scan --no-details` | Discover only; skip detail reads entirely. |
| `hunter sync` | Alias for `scan`, for manual runs. |
| `hunter programs` | List known programs. |
| `hunter programs --eligible` | Only programs the profile accepts. |
| `hunter programs --new` | Only programs first seen in the last scan. |
| `hunter programs --changed` | Only programs that changed in the last scan. |
| `hunter explain <id>` | Show the full decision, check by check. |
| `hunter history <id>` | Show recorded changes over time. |
| `hunter replay <id>` | Merge saved change history and opportunity windows into a read-only timeline. |
| `hunter alerts` | List recorded alerts. |
| `hunter alerts --undelivered` | Only alerts not confirmed delivered. |
| `hunter windows` | List recorded opportunity windows and their current status. |
| `hunter windows --open` | Only windows still within their configured age and crowding bounds. |
| `hunter windows --program <id-or-slug>` | Filter windows to one program. |
| `hunter validate-config` | Parse and validate the profile. |
| `hunter test-fixtures` | Re-parse the recorded upstream pages. |
| `hunter version` | Print the build version. |

Every command accepts `--json` for machine-readable output and scriptable use.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | The command failed. |
| `2` | The configuration is invalid. |
| `3` | The scan ran, but its results are **untrustworthy**. |

Code `3` exists because silence from a broken scan and silence from a quiet
platform look identical. The scheduled workflow treats `3` as a warning and
`1` as a failure, so a broken scan can never be mistaken for "no news".

---

## Configuration

Everything the system considers relevant lives in
`configs/profiles/personal.yaml`. Changing what you want to hear about is a
configuration edit, never a code change.

```yaml
profile:
  name: personal

  access:
    max_reputation_points: 80
    max_submission_fee_usd: 5
    kyc_required: no
    poc_required: yes
    accept_unknown_access_gates: false
    accept_unknown_parse_state: false

  target_domains:
    included: [web_application, api, backend, cloud, infrastructure, codebase, web2]

  crypto:
    enabled: true
    mode: auto
    require_allowed_trait: true
    allowed: [crypto_platform, exchange, crypto_api, crypto_backend]
    excluded: [smart_contract_only, solidity_only, protocol_consensus]
    dominance_ratio: 0.6

  program_states:
    allowed: [live, new]
    # States worth an alert independently of other changes (e.g., a reactivation).
    # When set, every alert requires the current state to be listed; when empty,
    # no additional gating applies beyond the normal eligibility checks.
    alert_on_state: [live, new, paused, ended]
    # States that independently warrant an alert. Every alert requires the
    # program to currently be in a listed state; an empty list disables the
    # gate. This separates "evaluate and track" (allowed) from "wake the
    # researcher" (alert_on_state).
    alert_on_state: [live, new]

  notifications:
    enabled: true
    min_severity: medium
    require_eligible: true
    alert_on_new_programs: true
    new_program_window: 24h
    alert_on_material_change: true
    alert_on_newly_eligible: true
    alert_on_scope_expansion: true
    change_windows:
      default: 72h
      scope_expansion: 72h
      access_improved: 168h
      reactivated: 72h
      bundle_window: 0s
      # If omitted, max_age is the widest change window above.
      max_age: 168h
      # Zero disables submission-count crowding expiry.
      max_post_change_submissions: 0
    max_per_scan: 10
    subject_prefix: "[HUNTER]"

  scan:
    per_page: 10
    max_pages: 0                  # 0 traverses the whole listing
    fetch_details: true
    fetch_details_on_listing_change: true
    details_refresh_interval: 24h
    request_timeout: 45s
    max_retries: 3
    retry_base_delay: 2s
    max_retry_delay: 30s
    min_request_interval: 400ms
    max_concurrent: 4
```

Parsing is strict: an unknown key or an unrecognised enum value is an error, not
something quietly ignored. A misspelled policy key that silently disabled a
filter would remove exactly the alerting you depend on.

Run `hunter validate-config` to see exactly how your profile was interpreted.

---

## Why unknowns are never treated as safe

The single most important safety property in this system:

> **A parsing uncertainty must never silently become an eligibility approval.**

Every access-critical fact is three-valued: `yes`, `no`, or `unknown`. `unknown`
means the source did not tell us, the page changed shape, or the parser declined
to guess.

A missing reputation requirement is reported as *observed to be absent* only when
the surrounding record parsed successfully. If the record itself could not be
understood, the fact stays unknown, and an unknown fact **blocks** approval
unless the profile explicitly opts in with `accept_unknown_access_gates: true`.

Concretely, this means:

- A broken parser produces **silence**, never a flood of false positives.
- `hunter explain` always shows whether a rejection was a real violation or an
  unreadable fact, and never conflates the two.
- A partially understood record is quarantined rather than trusted.

You can see it:

```
Policy checks:
  [pass]  data.parse_trust
          fully understood (access facts present)
  [UNKNOWN] access.submission_fee
          submission fee must be affordable is unknown: the platform states fees
          in the account currency, which cannot be compared to a USD ceiling
```

---

## What an alert looks like

```
Subject: [HUNTER] — NEW MATCH — Poloniex Web & API — API/Web — 8m

NEW QUALIFYING OPPORTUNITY
============================

Program:   Poloniex Web & API
Detected:  8m ago
State:     live

Access:
  reputation:       50 reputation points
  kyc:              KYC is not required
  submission fee:   $0.00
  proof of concept: required

Attack surface:
  api, web2, web_application
  capabilities: api, authentication, authorization, payments, trading, user_accounts
  + [api] https://api.poloniex.com
  + [web] *.poloniex.com

Crypto classification:
  kind:   crypto_platform
  traits: crypto_api, crypto_platform, crypto_web_application, exchange

Competition (reported by platform):
  4 submissions

In scope:
  + https://api.poloniex.com
  + *.poloniex.com

Why this matched:
  50 reputation points (within the configured maximum of 80)
  KYC is not required (profile does not require KYC)
  no submission fee
  program state is live (one of: live, new)
  exposes api, web2, web_application (one of: web_application, api, backend)

Attention priority: 83/100 (ordering aid, not a success estimate)
  access delta          50  no typed access-gate delta in bounded evidence
  bounty                70  ceiling $1500
  change magnitude      60  3 weighted change events
  eligibility          100  8 of 8 requirements satisfied; eligible
  freshness            100  first seen 8m ago
  low competition       84  4 submissions reported by the platform
  post-change competition  50  opening baseline or current count is unknown
  scope richness        50  2 in-scope assets
  surface relevance    100  matches api, web2, web_application

Timing:
  - program age: 4y ago
  - first seen: 8m ago

Open:
https://hackenproof.com/programs/poloniex
```

The score and component values are ordering heuristics, not measurements of
success. Submission counts and signed movement are printed as the raw figures the
platform published; they are weak proxies for competition, and framing them as
researcher counts would overstate what is known.

---

## Triage scoring is not a prediction

The score orders attention. It does **not** estimate whether you will find
something, and it never claims to.

Every component is published with its own value and a one-line basis, so the total
can always be traced back to observed facts, and you can disagree with any single
input. The `access delta` component counts only typed, directional gate changes;
it does not parse prose or fuse several facts into a claim. The `post-change competition`
component applies the existing submission-count curve to signed movement from
the latest opportunity window's opening baseline. Unknown baselines stay neutral,
and a negative movement remains visible. These and the existing
`low competition` component contribute to one weighted total, not separate
scores. Bounty size is weighted lowest on purpose: a large bounty is not evidence
of an easier bug, and weighting it heavily would bias the channel toward whoever
pays most.

---

## Change detection and opportunity windows

Change is detected by comparing **content**, never by trusting page timestamps.
Fingerprints cover three disjoint subsets, so a change lands in exactly the signal
that describes it:

| Fingerprint | Covers |
|---|---|
| scope | the in-scope asset set and technical surface |
| requirements | access gates and participation constraints |
| metadata | identity, classification, bounty, state |

The diff keeps directional evidence atomic. Examples include `API_ADDED`,
`ASSET_MOVED_IN_SCOPE`, `REPUTATION_LOWERED`, `KYC_REMOVED`, `FEE_REDUCED`, and
`POC_REMOVED`; the opposite movements are recorded separately and do not open a
window. An unreadable gate has no direction. Summary events such as
`SCOPE_CHANGED` and `SURFACE_CHANGED` are alertable only when their recorded
direction is improved access.

Every change is bounded by an `ObservationInterval`: the last detail read that did
not show it and the first read that did. Hunter does not claim to know the instant
between those reads. Human output shows the youngest-to-oldest possible age range;
unknown or unbounded changes alert on nothing. Each trigger has its own recency
window, resolved from a per-kind setting, then a change class, then `default`.

An opportunity window is a temporal bundle, not a rewritten editorial conclusion.
It carries each directional delta separately, plus the submission count observed
when it opened and the signed count movement seen later. `hunter windows` shows
these records and derives `open` or `expired` from the current age and optional
crowding thresholds. An unbounded window is expired rather than presumed fresh.

`hunter replay <id>` merges a program's saved change-history entries and windows
into a read-only timeline. It shows scan-recorded times separately from bounded
observation intervals, preserves each atomic delta, and reports saved eligibility
without re-running policy, scoring, alert generation, or source reads. The order is
by the earliest available evidence; overlapping intervals remain visibly bounded,
not converted into a claimed event time.

A change alert for a long-running program is therefore presented as a change (for
example, `PROGRAM CHANGED`) with its own observed-age range, not as `NEWLY
LAUNCHED`. The program's source-reported launch age remains a separate fact.

---

## Why it is fast: the two-tier read

A naive implementation fetches every detail page on every scan. Against ~320
programs on a five-minute cadence that is tens of thousands of requests a day, and
it produces scans measured in minutes.

Hunter reads in two tiers:

- **The cheap tier** sweeps the listing for every program on every scan. The
  listing exposes lifecycle state, bounty, the classification labels, and a
  submission count — enough to detect that something moved.
- **The expensive tier** reads a detail page only when the listing says something
  differs, when the record has never been completed, or when the refresh interval
  has elapsed.

The profile's refresh interval is the normal upper bound. If a scope,
requirements, metadata, or lifecycle change has a bounded interval that is still
**definitely** inside the configured opportunity horizon, Hunter shortens that
program's refresh interval to one quarter of the configured value. The faster
follow-up ends when the recorded interval is no longer definitely recent; stable
programs keep the normal cadence. This adaptation runs inside the single-shot
scan, with no daemon or second scheduler.

Two things are deliberately excluded from the trigger, because both change
constantly and would otherwise defeat the whole design:

- **The submission count** rises on active programs continuously. It is recorded
  as an observation and used for triage, but it never triggers a detail read.
- **The platform's `scopeReview` counter** increments on *every page render*. It
  is not a revision, so it is neither compared nor persisted — storing it would
  produce a diff on every single run for no benefit.

Measured against the live platform (~324 programs, 33 listing pages):

| | Duration | Detail reads |
|---|---|---|
| Every scan fetches everything | ~9m 20s | 324 |
| Two-tier, initial pacing | ~1m 30s | 324 |
| Two-tier, tuned | **~45s** | **0** |

A steady-state scan now performs **zero** detail reads while still evaluating all
324 programs and keeping every eligibility decision current.

---

## State

State lives in the repository so it is reviewable and recoverable:

```
state/
  programs.json          current record per program
  alerts.json            alert delivery records
  windows.json           opportunity windows and competition observations
  history/<program>.json per-program change history
```

Properties the implementation guarantees:

- **Atomic writes.** Every file is written to a temporary file, synced, and
  renamed. An interrupted run cannot leave a half-written file.
- **Deterministic serialization.** Identical inputs produce identical bytes, so
  a scan that learned nothing new produces no diff. Maps are sorted on output;
  volatile fields are excluded.
- **Corruption is reported, never discarded.** Starting from an empty snapshot
  would make every known program look new and fire an alert for all of them. A
  damaged file is a loud error so a human can restore from version control.
- **Bounded history.** Retained history is capped per program.

---

## Architecture

```
cmd/hunter                     single-shot binary

internal/
  domain/                      canonical model; imports nothing internal
    tristate.go                the yes/no/unknown type
    program.go, target.go      the stable records
    crypto.go                  the crypto taxonomy
    decision.go                explainable policy verdicts
    change.go, alert.go        change events and notifications
  canon/                       byte-stable JSON
  config/                      profile loading and validation
  source/
    source.go                  ProgramSource contract, sentinels
    httpclient.go              retries, backoff, pacing, pooling
    devalue/                   decoder for the source's embedded payload
    hackenproof/               the HackenProof adapter
  normalize/                   source records -> domain; classification
  policy/                      eligibility, one check at a time
  diff/                        content-based change detection
  scoring/                     deterministic triage
  alerts/                      selection, rendering, fingerprinting
  notify/                      delivery, with idempotency
  state/                       StateStore contract and file implementation
  pipeline/                    orchestration
  cli/                         commands
  obs/                         structured logs and metrics
```

Dependencies point inward. `domain` imports nothing else in the project, so the
model cannot be dragged along by an adapter or a notifier.

### Adding a platform

Implement two methods and register it once:

```go
type ProgramSource interface {
    Name() string
    Discover(ctx context.Context) ([]domain.ProgramRef, error)
    Fetch(ctx context.Context, ref domain.ProgramRef) (domain.RawProgram, error)
    Capabilities() domain.SourceCapabilities
}
```

Nothing outside `internal/source` changes. Discovery, detail retrieval, and
eligibility stay separated, so an adapter never decides what is relevant.

### Adding a notification channel

```go
type Notifier interface {
    Send(ctx context.Context, alert domain.Alert) error
    Name() string
    Configured() bool
}
```

Idempotency lives in the dispatcher, so a second channel inherits it for free.

### Replacing the state backend

```go
type StateStore interface { /* Load, Save, alert and history records */ }
```

A database can replace the file implementation without any business logic
changing.

---

## Observability

Every scan emits one greppable line:

```
scan_id=20261002T215638Z source=hackenproof discovered=324 evaluated=324
fetched=0 listing_only=324 new=0 changed=0 minor_changed=5 eligible=156
rejected=168 alerts=0 sent=0 failed=0 errors=0 duration=43.75s
```

`changed` counts material changes only, which is the same meaning the
`programs --changed` filter and the change history give it. Low-severity
observations such as a moving submission count are reported separately as
`minor_changed` rather than being counted as changes, so the summary line and the
commands that query it never disagree.

When a run is untrustworthy, it says so and says why:

```
scan_id=... WARNING: no programs could be evaluated
         Silence from a degraded scan does not mean absence of opportunities.
```

Fault isolation is deliberate throughout: a panic while handling one program, a
program that cannot be fetched, or a source that is entirely down degrades
coverage instead of ending the scan. A failing email provider never prevents
state from being recorded, and a recorded alert survives a delivery failure so the
next run can retry it.

---

## Testing

```bash
make test        # full suite
make race        # race detector (needs cgo and gcc)
make check       # what CI runs
```

The suite covers policy combinations, normalization determinism, every change
event, alert generation and deduplication, delivery idempotency, and the failure
model: timeouts, HTTP 429, HTTP 500, malformed pages, missing fields, email
failure, and state corruption.

Tests never touch the network. Pages captured from the live site are checked in
under `fixtures/`, and assertions are pinned to those bytes — so the parser stays
verifiable after the upstream site changes, and `hunter test-fixtures` re-verifies
it before any live scan trusts it.

Several tests exist specifically to pin bugs that were found and fixed, because
each was invisible in output and expensive in practice:

- `TestListingChangedSinceIsNotInverted` — a negated comparison made every
  program re-fetch on every scan.
- `TestNewProgramWithoutLaunchDate` — a nil-pointer dereference on any program
  with no launch date.
- `TestListingTriggerIgnoresVolatileFields` — a per-render counter used as a
  change trigger.

---

## Scheduling

The `deploy/systemd/hunter.timer` unit invokes `hunter scan` every five minutes.
Systemd is the scheduler; GitHub Actions is not used for live scans. Each
invocation is a single-shot worker with no server and no listening socket: it
reads the source, writes state, optionally sends email, and exits.

The state directory is persisted by the host deployment and is decision-making
evidence: preserve and commit its contents to version control. No second
scheduler should scan into a separate state store, because the two histories
would diverge and could send duplicate alerts.

`.github/workflows/test.yml` runs formatting, vet, build, and the full suite on
pushes and pull requests. It does not schedule production scans.

---

## Email credentials

Read from the environment only. Never in the repository, never in the profile,
never in state, never in logs.

| Variable | Purpose |
|---|---|
| `EMAIL_SMTP_HOST` | SMTP server |
| `EMAIL_SMTP_PORT` | SMTP port |
| `EMAIL_USERNAME` | Username, also used as the From address |
| `EMAIL_PASSWORD` | Password or app token |
| `ALERT_RECIPIENT` | Recipient; comma-separated for more than one |
| `EMAIL_FROM_NAME` | Optional display name |

With any of them missing, alerts are still generated, scored, and recorded — the
run simply reports that delivery was skipped.

---

## Data and terms

This system reads only what the platform already serves to every unauthenticated
visitor. Specifically:

- It has **no credentials, no cookie jar, and no session handling**. It does not
  read anything behind a login.
- It **does not defeat** CAPTCHA, bot protection, rate limits, or any other access
  control. A 403 is a terminal failure, not a problem to solve.
- It respects `robots.txt` and paces every request (`min_request_interval`).
- It sets a truthful, stable User-Agent identifying itself as a research monitor.
- TLS verification is on. The insecure override exists but is never enabled
  automatically, and credentials are about to be sent over that connection.

Program descriptions are read for classification only and are never inlined into
alerts. Nothing scraped is ever executed, and no scraped content becomes
configuration.

If the platform later offers an authorized API or a licensed feed, it becomes a
second adapter. The engine does not change.

---

## Development

```bash
make help              # list targets
make build             # build
make test              # run the suite
make race              # race detector
make fixtures          # re-parse recorded upstream pages
make scan              # dry-run scan against the live source
make release           # reproducible binaries into dist/
```

Bash is used only for thin wrappers and CI. There is no Python, no Node, and no
JavaScript runtime anywhere in the build, the tests, or the tooling.
