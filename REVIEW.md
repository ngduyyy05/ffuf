# Business logic review — 2026-10-31

Scope: source review and regression tests against the bundled local Flask lab.
No external target was scanned. This repository is a Python API discovery CLI,
not the upstream Go ffuf tool and not a full web vulnerability scanner.

## Fixed

- Absolute URLs in wordlists could redirect requests and custom authentication
  headers to another host. Paths now reject schemes, authorities, backslashes,
  and fragments before requests are sent.
- ID values could alter path/query structure. Values are now percent-encoded.
- JSON 404 errors were always marked interesting. 404/410 responses are now
  excluded, as are exact status/type/full-body matches to a method baseline.
- GET-only baseline comparison was incorrect for other HTTP methods. Each
  method now gets its own baseline and all requests use the same pacing.
- Keyword substring matching produced signals such as `id` in `video`.
  Matching now checks token boundaries; vendor JSON and all 5xx are supported.
- Resource `id` was called an owner field. Only `user_id`/`owner_id` retain
  that label. IDOR candidates use GET responses and exclude baseline matches.
- Invalid numeric options now fail before networking. Missing template IDs,
  malformed targets, empty wordlists, and malformed headers fail early.
- Added static request bodies, HEAD support, session cleanup, and interrupt exit.

## Remaining limits

- IDOR results are low-confidence candidates. Different public resources can
  legitimately return different bodies. There is no two-principal comparison,
  known ownership mapping, or application-specific authorization policy yet.
- Exact baseline matching cannot remove dynamic catch-all pages. Per-route
  baselines and repeated sampling would improve precision further.
- Responses are buffered in memory and JSON/body previews are saved in reports.
  Very large responses need streaming limits; sensitive reports need controlled
  storage and future configurable redaction.
- POST/PUT/PATCH/DELETE can mutate application state, including baseline probes.
  Select methods appropriate to the authorized test environment. Static body
  support does not implement stateful workflows or body parameter fuzzing.
- No crawling, OpenAPI import, concurrency, scan resume, or confirmed exploit
  validation. These require separate design and tests.

## Verification

`python -m pytest -q`: includes URL scope and input validation, encoded IDs,
soft-404 filtering, JSON media types, keyword matching, existing IDOR tests,
and real localhost HTTP requests to the bundled vulnerable orders route plus
protected and missing routes. JSON, CSV, and Markdown exports are exercised.
