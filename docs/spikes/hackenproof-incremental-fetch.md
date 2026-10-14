# HackenProof incremental-fetch spike

**Measured:** 2026-10-13 (UTC), live from the deployed host (`vps3602694`,
same egress Hunter uses, same User-Agent). This supersedes the 2026-10-05
note below, whose sort-UI claim did not survive byte-level inspection.

**Decision (unchanged, now with evidence):** do not add listing-driven
incremental discovery or conditional HTTP requests. Poll everything every
scan; the adaptive detail-refresh already implemented is the correct
mechanism, not a changed-set feed.

## 1. Response validators: absent, not unknown

Unauthenticated `HEAD /programs`, `HEAD` + `GET` on a detail URL
(`/programs/flipster-web-and-mobile`), captured with headers:

| Surface | `ETag` | `Last-Modified` | `Cache-Control` | Other |
|---|---|---|---|---|
| `GET /programs` | absent | absent | absent | `cf-cache-status: DYNAMIC`, `x-powered-by: Nuxt`, `vary: Accept-Encoding` |
| `HEAD /programs` | absent | absent | absent | same |
| `GET` detail | absent | absent | absent | same |
| `HEAD` detail | absent | absent | absent | same |

There is nothing to validate against, so conditional requests cannot exist
here. `source.Client.attempt()` returning only a body is therefore not a
limitation to fix — exposing validators would change the shared HTTP-client
contract for zero benefit. Do not revisit unless a future header capture
shows validators.

## 2. Updated sort: does not exist on the public listing

- The listing HTML contains **no** sort control: no "Newest to Oldest" /
  "Oldest to Newest" text, no sort `<option>`/links, no `sort=`/`order=`/
  `sort_by=`/`ordering=`/`direction=`/`sortKey` parameters anywhere.
- The earlier note's claim that the rendered page "exposes" an updated sort
  came from a page-fetch tool summary, not from the bytes. It is retracted:
  the sort UI, if it exists at all, is not on the unauthenticated listing.
- Five candidate sort query strings were fetched live (`?sort=updated_at`,
  `?order=desc`, `?sort_by=updated_at`, `?ordering=-updated_at`,
  `?sort=newest`). Initial results *looked* like three of them reordered the
  listing — but a repeatability check disproved it: two identical
  `?sort=updated_at` fetches returned **different** orders, and a plain
  refetch matched one of them exactly. The listing order varies
  fetch-to-fetch on its own; no parameter is honored.
- The observed orders are not update-monotonic anyway (e.g. 14 Oct, 28 Sep,
  14 Sep, 17 Sep, 02 Oct down the first ten rows).

Consequences, all already handled by current code and kept as-is:

- Poll-everything-every-scan remains the only complete discovery strategy.
- The adapter's dedup-by-slug plus unproductive-page cutoff is load-bearing
  against ordering instability, not optional. Do not "simplify" it.
- A sort would not have been a filter in any case: stopping pagination early
  would still require proving stability sufficient to miss no same-day
  update, which the observed instability directly contradicts.

## 3. Company identifier: does not exist

The detail payload carries `companySlug` (e.g. `"flipster"`) and
`companyName` only. No numeric `companyId` / `orgId` / `organizationId`
exists in any observed payload. A slug is renameable display metadata, not
identity — `HasStableIDs` remains false, and organization-level correlation
stays deferred rather than inferred. No change.

## 4. Incidental confirmations (not decisions)

- Per-program `lastUpdated` (day resolution, e.g. `"14 Oct 2026"`) is present
  in the listing payload and is already consumed as Hunter's coarse change
  bound. Unchanged.
- The listing exposes filter attributes (`by_status`, `by_kyc`, `by_poc`,
  `reputation_up_to`, `submission_fee_up_to`, `search`). Server-side
  filtering was not measured; it is out of scope for this spike. If a future
  spike measures it, the honest questions are whether filters are honored
  server-side and whether filtered-out programs vanish silently (a coverage
  interaction), not whether they replace change detection.

## Decision (restated with evidence)

1. Keep `SupportsIncrementalFetch: false`; keep content comparison and the
   bounded periodic + adaptive detail refresh.
2. Do not add `If-None-Match` or `If-Modified-Since`, now for a stronger
   reason than before: measured absence, not unknown.
3. Do not build an `updated`-sort fast path: there is no sort to use, and
   the listing order is unstable fetch-to-fetch.
4. Do not infer organization identity from company slugs.

---

## Appendix: superseded 2026-10-05 note

Retained for provenance; its two load-bearing claims are corrected above
(sort UI existed only in a tool summary, never in the bytes; validators were
unknown then, now measured absent).

The three checked-in body fixtures were parser fixtures (response bodies
only), never validator evidence: they contain no headers. The spike makes no
claim about headers that are not stored in them. The attempted public-page
reads with candidate query keys referenced there predate the repeatability
check that settled the question.
