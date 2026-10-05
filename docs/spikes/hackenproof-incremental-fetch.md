# HackenProof incremental-fetch spike

**Observed:** 2026-10-05 (UTC)

**Decision:** do not add listing-driven incremental discovery or conditional HTTP
requests yet.

## Evidence inspected

The three checked-in body fixtures used for this spike are:

| Surface | Fixture | Observation |
|---|---|---|
| `/programs` listing | [`listing-page1.html`](../../fixtures/hackenproof/listing-page1.html) | The rendered page exposes `Updated at: Oldest to Newest` and `Updated at: Newest to Oldest`. The captured serialized page data also contains `updated_at`. |
| Bitrue detail | [`program-bitrue.html`](../../fixtures/hackenproof/program-bitrue.html) | The page links its company label to `/companies/bitrue`. |
| Starknet Staking detail | [`program-starknet-staking.html`](../../fixtures/hackenproof/program-starknet-staking.html) | The page links its company label to `/companies/starknet`. |

The listing therefore exposes an **updated sort** in its UI, but the fixture does
not establish the exact request contract or that sorting yields a changed-only
set. The attempted public-page reads with candidate query keys were normalized by
the page-fetch tool to the same canonical listing and did not reveal which request
the site's UI sends. A sort also is not itself a filter: even a working descending
sort would still require proving that the complete ordering is stable enough to
stop pagination without missing same-day updates.

The two detail pages expose company route slugs, not a durable company ID. The
slug is useful display/link metadata, but these captures do not prove it is
immutable or globally unique. `HasStableIDs` should remain false.

## Validator check

The available page-fetch interface returns rendered page content but not HTTP
response headers. Direct HTTP access from this sandbox is unavailable, so neither
`ETag` nor `Last-Modified` nor `Cache-Control: no-store` was observed. This is an
**unknown**, not evidence that validators are absent. No response-header fixture
was fabricated.

For a conclusive follow-up, capture unauthenticated `HEAD` and `GET` response
headers for both `/programs` and one detail URL from the deployed host, using the
same User-Agent as Hunter. Record status, `ETag`, `Last-Modified`, `Cache-Control`,
`Vary`, and redirect behavior. Keep cookies out of the capture.

## Decision

1. Keep `SupportsIncrementalFetch: false`; keep the current content comparison and
   bounded periodic detail refresh.
2. Do not add `If-None-Match` or `If-Modified-Since`. `source.Client.attempt()`
   currently returns only a body; exposing validators would change the shared
   HTTP-client contract. That cross-cutting change is not justified until the
   source is shown to return useful validators.
3. Revisit listing sort only after capturing the UI's actual request and testing
   its ordering across pages, ties, and day-resolution updates. Even then, it may
   be an optimization, not a replacement for periodic detail reads.

The three fixtures above remain parser fixtures, not validator evidence: they
contain response bodies only. The spike makes no claim about headers that are not
stored in them.
