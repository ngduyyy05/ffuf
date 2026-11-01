# Project audit and verification — 2026-11-01

## A. Project Audit Summary

Scope: all tracked Python sources, tests, lab, sample wordlist, requirements,
README, prior review and repository configuration were read. Source changes were
made directly in the workspace; nothing was pushed or merged. HTTP tests used
127.0.0.1 only. Package installation/auditing contacted package infrastructure,
not third-party API targets.

Architecture: main.py delegates to cli.py. utils.py validates inputs and owns
result models. fuzzer.py plans/paces route-method-profile requests and baselines;
requester.py owns isolated Requests sessions, bounded streaming and retries.
analyzer.py evaluates endpoint signals; idor.py evaluates resource comparisons
and explicit access expectations. reporter.py writes sanitized outputs.
profiles.py now strictly loads authentication/policy JSON. lab/app.py provides
intentional vulnerabilities and a protected control. Tests use both the bundled
lab and temporary HTTP fixtures.

Strengths retained: small modules, session reuse, TLS verification, disabled
redirect following, URL-encoded IDs, supported legacy CLI, explicit 404 exclusion
and low-confidence heuristic language. The original 20 tests passed before
changes. Existing functionality was preserved where compatible with stricter
validation and privacy defaults.

Weaknesses found: unbounded response buffering and ID expansion, incomplete
header/path validation, unredacted reports, persistent server cookies, no retry,
route-independent baselines, insufficient multi-principal evidence, no packaged
entry point or CI, and limited edge-case testing. There was no OpenAPI importer,
async engine, JSON field mutation, generic scan config or SARIF despite these
being reasonable future enhancements; the original README listed them as roadmap,
not working features.

## B. Bugs Found & Fixed

| File | Issue | Severity | Root Cause | Fix | Test Result |
| --- | --- | --- | --- | --- | --- |
| utils.py | Huge ID ranges can exhaust RAM | High | Eager unrestricted range expansion | Pre-expansion 10000 ID bound; bounded files and paths | ID expansion/range tests pass |
| utils.py, fuzzer.py | Traversal can escape base prefix or fail after scan begins | High | urljoin resolves dot segments; expanded paths not preflighted | Reject encoded/plain dot segments, controls, backslashes; validate all expanded paths before networking | Scope and encoded-ID tests pass |
| requester.py | Large responses consume unrestricted memory | High | response.text/content fully buffer bodies | Streaming decoded prefix cap; truncated results have no full hash/JSON and cannot confirm findings | Real large-response and truncation tests pass |
| fuzzer.py | Excessive scan expansion and retained bodies | High | No combined attempt/response budget | Worst-case preflight before expansion; global attempts and aggregate 8 MiB response-prefix stop | Planning and aggregate budget tests pass |
| reporter.py | Body/query secrets exported in reports | High | Raw result serialization | Omit bodies/previews; redact all query values and URL userinfo across terminal/JSON/CSV/Markdown/HTML | All export redaction tests pass |
| utils.py, requester.py | Invalid headers/cookies fail late or alter framing | Medium | Incomplete CRLF/encoding/name validation | Reject controls before stripping, non-Latin-1 values and managed Host/framing headers; validate API/CLI inputs | Header/cookie tests pass |
| requester.py | Server cookies silently change test principal | Medium | Session cookie jar persists between probes | Static explicit Cookie only; clear jar before/after attempts; isolated profile sessions | Real cookie isolation test passes |
| requester.py | Environment netrc/proxy silently changes credentials/routing | Medium | Requests trust_env default | Disable trust_env; explicit credentials only | Isolation test passes |
| idor.py | HTTP 200 error envelopes generate IDOR signals | Medium | Only transport status considered | Exclude recognized error/success=false/problem/status/message envelopes | Error envelope tests pass |
| fuzzer.py | Root baseline misses route catch-all responses | Medium | One random root probe per method | Sibling/placeholder baseline per route, method and profile | Local route-fallback test passes |
| cli.py, fuzzer.py | Ctrl+C discards completed scan results | Medium | Immediate return before report generation | Capture interruption, export partial results and stop reason, close sessions, exit 130 | Injected cancellation and CLI export tests pass |
| cli.py | Report permission errors raise unhandled traceback | Medium | Output writes outside error handling | Actionable error and exit 1 | Injected PermissionError test passes |
| reporter.py | HTML/Markdown injection and CSV formulas | Medium | Unescaped untrusted fields | Escape generated markup and neutralize formula-leading cells | Escape/formula tests pass |
| reporter.py, utils.py | Malformed redirect Location crashes export; URL userinfo leaks | Medium | Untrusted Location passed directly to urlsplit/export | Invalid URL placeholder and userinfo stripping | Redirect sanitization tests pass |
| analyzer.py, idor.py | Deep JSON can crash recursive analysis | Medium | Recursive field walk and unguarded serialization | Bounded iterative field search, serialization guards, scalar owner values | 2000-level JSON tests pass |
| idor.py | One profile's identical bodies can mask another profile's evidence | Medium | Chosen principal before evaluating variation | Compare profiles independently, select an evidence-bearing candidate | Multi-profile regression test passes |
| idor.py | Pairwise evidence search scales quadratically | Low | Nested search over every successful sample | Index authorized responses by ID/full hash | Multi-principal evidence regression passes; no throughput benchmark claim |
| reporter.py | HTTP 5xx other than 500 absent from error totals | Low | Equality check against 500 | Count all 5xx, separate network-error totals | HTTP status/summary integration passes |

## C. Improvements Implemented

- Positive finite timeout/rate validation, 0-5 retries and bounded response sizes.
- GET/HEAD/OPTIONS retries on network errors and 429/502/503/504, exponential
  backoff and capped numeric Retry-After. Mutating methods are not retried.
- Shared pacing across probes, methods, profiles and retries; sequential default.
- Optional JSON string-content ID substitution in request bodies; static bodies
  remain the default. UTF-8 bodies are explicitly encoded.
- Strict JSON authentication profile files with allow/deny/public route policies;
  credentials cannot be accidentally mixed with global headers/cookies.
- Four route classifications, findings with confidence/evidence, and separate
  401/403 counts. Confirmed requires an explicit deny expectation and an exact,
  complete response match to another explicitly allowed profile for the same ID.
  Heuristics alone always remain Potential IDOR.
- Status/minimum-size/content-type filtering without discarding diagnostic data
  or suppressing the independent authorization analysis.
- Sanitized JSON/CSV/Markdown plus escaped standalone HTML, summary statistics,
  retained baseline metadata and partial-scan state. JSON is canonical; CSV is
  explicitly a request table rather than an equivalent nested finding format.
- Installable wheel/console entry point, runtime/dev dependency separation,
  documented source installation compatibility, Ruff checks and CI matrix.
- Protected lab control route; Flask debug disabled; sample/profile examples.
- Rewritten README, lab guide and superseded prior review.

Intentional behavior changes: unsafe headers/paths/ranges fail early; environment
proxy/netrc and server-set cookies are ignored; report bodies/previews are empty;
baseline request counts increase with route/profile count. Existing field names
are retained and metadata fields are additive. The version is now 0.2.0.

## D. Test Results

Executed on Windows, Python 3.13.14. Final source suite:

- Collected/executed: **99**; passed: **99**; failed: **0**; skipped: **0**.
- Statement coverage: **94.8747%** (833/878 statements; console rounds to 95%).
- Original 20 tests remain passing. New tests exercise unit, integration,
  regression, validation, network faults, exports, budgets and cancellation.
- `python -m ruff check .`: pass, including import sorting, Python modernization
  and Bugbear rules. `python -m ruff format --check .`: pass.
- `python -m compileall -q apifuzz lab main.py`: pass.
- `python -m pip check` in the clean virtualenv: pass.
- Clean virtualenv installation with `pip install -e ".[dev]"`: pass.
- Wheel build and wheel reinstall: pass; installed CLI help/import were also
  checked outside the source directory.
- README examples ran as actual subprocess CLI commands against an ephemeral
  port on the bundled localhost lab. The GET example produced 15 results and
  all four exports; two-profile example produced 22 results, public users as
  No Issue Observed, vulnerable orders as Potential IDOR, and the protected
  order control as No Issue Observed. POST body example completed with expected
  405 responses because the bundled lab does not implement POST resource routes;
  real POST/PUT/PATCH/DELETE JSON template success is covered by echo fixtures.
- Installed CLI `--help` verified. Report JSON was parsed and CSV rows read back;
  Markdown/HTML presence, escaping and sensitive-data omission were asserted.
- `git diff --check`: pass (Git also emits repository CRLF conversion notices).

Dependency security: clean environment initially reported two duplicate advisory
entries for one pip issue at version 26.1.2. Upgraded **only the audit virtualenv**
to pip 26.2.2 and reran pip-audit: no known vulnerabilities reported for audited
packages. The unpublished local apifuzz-lab package is skipped by the package
advisory service; it is covered by this source audit and tests. This is a dated
result for installed versions, not a guarantee for all versions allowed by ranges.

Not executed: hosted GitHub Actions, Python 3.10/other interpreters, Ubuntu/macOS,
real production targets, a real TLS server with certificate fixtures, real OS
Ctrl+C signal delivery, adversarial long-duration slow streams, sustained memory
or throughput benchmarks. KeyboardInterrupt, permission errors and interrupted
response streams were injected; ordinary timeouts/refused connections were real
localhost requests. No third-party target was fuzzed.

Local artifacts (gitignored): `reports/coverage.json`,
`reports/dependency-audit.json`, `reports/readme-lab.{json,csv,md,html}`,
`reports/readme-profiles.json`, `reports/readme-body.json`,
`reports/wheels/apifuzz_lab-0.2.0-py3-none-any.whl`. The audit virtualenv is
`.venv-audit/`; application sources were not committed automatically.

## E. Security Findings

High-priority input/resource/report issues above are fixed and regression-tested.
TLS verification and redirect refusal were preserved. No shell execution,
untrusted pickle/YAML loading, eval, or command-construction path was found.
The new profile loader uses strict JSON only. Report outputs are caller-selected
paths and can overwrite files intentionally, consistent with the existing CLI.

Residual scope risks: the CLI intentionally accepts the user's chosen HTTP(S)
origin, including internal addresses. It is not a sandboxed SSRF proxy and has no
DNS/IP allowlist or DNS-rebinding protection; do not expose it as a public scan
service. Paths/IDs/profile names and hashes remain in reports and may be sensitive.
State-changing methods and their baseline probes can mutate data. Existing
vulnerable lab endpoints remain intentional and localhost-bound.

## F. Modified Files

| Files | Purpose |
| --- | --- |
| main.py | Import formatting only; same entry behavior |
| apifuzz/__init__.py | Version 0.2.0 |
| apifuzz/utils.py | Models, input limits, scope/header/ID validation, query redaction, logging |
| apifuzz/requester.py | Bounded streaming, retry/backoff, credential isolation, templates, cleanup |
| apifuzz/fuzzer.py | Preflight budget, per-route/profile baselines, shared pacing, partial results, assessments |
| apifuzz/analyzer.py | Bounded field traversal and robust deep JSON handling |
| apifuzz/idor.py | Error-envelope exclusion, explicit policy evidence, indexed profile comparison |
| apifuzz/profiles.py (new) | Strict authentication/access-policy JSON loader |
| apifuzz/reporter.py | Sanitization, escaping, HTML, classifications and statistics |
| lab/app.py | Authenticated ownership control route and disabled debugger |
| tests/test_analyzer.py, tests/test_regressions.py | Formatting/import normalization; original regression assertions retained |
| tests/test_engine.py (new) | Local HTTP, CLI, policy, retry, body, budget and error integration tests |
| tests/test_safety.py (new) | Scope/input/redaction/deep JSON/profile comparison regressions |
| wordlists/sample_api.txt | Include protected ownership control |
| examples/profiles.json (new) | Two-principal lab policies |
| pyproject.toml (new) | Package build/entry point, dependency groups, pytest/Ruff configuration |
| requirements.txt | Compatible dependency upper bounds |
| .github/workflows/ci.yml (new) | Windows/Ubuntu, Python 3.10/3.13 quality and dependency checks |
| .gitignore | Audit/build/cache/coverage/private-profile artifacts |
| README.md, lab/README.md, REVIEW.md | Accurate current usage, limitations and audit pointer |
| AUDIT_REPORT.md (new) | This evidence-based audit report |

## G. Remaining Issues

- Dynamic soft-404 pages and application-specific HTTP 200 error formats may
  still evade heuristics. Public resources can yield Potential IDOR without
  public policies. No independent business-policy inference is claimed.
- Exact response matching is deliberately conservative: viewer metadata and
  timestamps can prevent confirmation. The bundled vulnerable orders route has
  viewer metadata and remains Potential IDOR with example profiles. A stable
  controlled fixture demonstrates confirmed findings against supplied policies.
- Ownership fields are bounded-search, scalar heuristics; unusual JSON schemas,
  collections and stateful workflows require manual validation.
- No async/concurrency, OpenAPI import, general scan config, generic matching DSL,
  structured JSON logs, live progress UI, SARIF, replay files, scan resume, token
  refresh or JSON field mutation. These were assessed and deferred to avoid
  expanding the scanner's scope without appropriate architecture/tests.
- Numeric Retry-After is supported; HTTP-date Retry-After falls back to backoff.
  Deadline checks between chunks are not a strict adversarial wall-clock bound.
- Aggregate retained-prefix stop can overshoot by one bounded response; Python
  JSON objects and transport buffers add overhead. No memory benchmark claim.
- Reports are not atomically replaced. Some selected outputs can exist if a
  later write fails. Filesystem permissions are inherited from the environment.
- Runtime dependency ranges are not a reproducible lock. Re-audit installed
  versions when building a release; hosted CI and cross-platform matrix remain
  unexecuted locally. Python 3.10 support is declared/configured, not locally proven.

## H. Final Evaluation

The core CLI is substantially better covered and is stable in the exercised
Windows/Python 3.13 localhost workflows. All 99 tests pass with no known failing
regression in that tested scope. Bounded reads/planning, session isolation and
sanitized exports address the most direct tool-side safety defects. Sequential
pacing and indexed policy comparisons improve predictability; throughput and
production readiness are not benchmarked. Findings now separate explicit
policy-backed evidence from low-confidence heuristics and insufficient data.

This is a reviewable 0.2.0 candidate for authorized lab/internal use. It is not
a universal authorization oracle or an unqualified production-release guarantee.
Before a public release, run the configured CI matrix and review the disclosed
limitations against the intended deployment environment.
