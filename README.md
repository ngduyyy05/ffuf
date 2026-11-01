# API Endpoint Fuzzer & IDOR Finder 0.2

Python CLI for API discovery and scoped authorization testing. Use only on
systems you own or have explicit permission to test. This is a Python project,
not the upstream Go ffuf. Default scanning is sequential at 5 attempts/second.

## Install

Python 3.10+ is required. Local verification used Windows and Python 3.13.14;
CI is configured for Python 3.10/3.13 on Windows and Ubuntu.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
apifuzz --help
```

On Linux/macOS use `source .venv/bin/activate`. `pip install .` installs only
runtime dependencies. `pip install -r requirements.txt` remains supported for
source-tree use, including the lab and pytest. Both `apifuzz` and
`python main.py` use the same CLI. No account or external service is required.

## Local quick start

In a separate terminal run `python lab/app.py`. It binds to 127.0.0.1:5000 with
debug disabled. Commands below are single lines, usable in PowerShell or Bash:

```text
python main.py --base-url http://127.0.0.1:5000 --wordlist wordlists/sample_api.txt --ids 1-3 --output reports/lab.json --csv-output reports/lab.csv --md-output reports/lab.md --html-output reports/lab.html
python main.py --base-url http://127.0.0.1:5000 --wordlist wordlists/sample_api.txt --ids 1-2 --profiles-file examples/profiles.json --output reports/profiles.json
```

Wordlists contain one relative path per line; blank lines and `#` comments are
ignored, a UTF-8 BOM is accepted, and identical entries are deduplicated.
`/api/orders/{id}` substitutes IDs from `--ids 1-3,alice` or `--ids-file ids.txt`.
ID files contain literal IDs, one per line, with optional comments; range
expansion applies to `--ids` only. Descending and negative ranges are supported.
Unknown placeholders and templates without IDs fail before any request.
IDs are percent-encoded. Dot-segment IDs and path traversal are rejected.
The base prefix is preserved: `/users` with base `http://localhost/api/` requests
`/api/users`. Only HTTP(S) targets without embedded credentials are accepted.
Wordlists cannot select another origin; redirects are never followed.

## Requests, limits and filters

| Option | Behavior / default |
| --- | --- |
| `--methods GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS` | Default GET; duplicates removed |
| `--header "Name: value"` | Repeatable; later case-insensitive name wins |
| `--cookie "session=demo"` | Explicit static Cookie header |
| `--timeout 8` | Connect and read timeout in seconds; positive finite |
| `--rate-limit 5` | Global maximum attempts per second, including probes/retries/profiles |
| `--retries 1` | 0-5 extra GET/HEAD/OPTIONS attempts on network errors or 429/502/503/504 |
| `--max-response-bytes 1048576` | Retained decompressed body prefix, allowed 1 byte to 16 MiB |
| `--max-requests 10000` | Preflight worst-case attempt budget, maximum 100000 |
| `--exclude-status 404,429` | Hide statuses from interesting results |
| `--min-size 10` | Minimum interesting body prefix size |
| `--content-type application/json` | Case-insensitive content-type substring filter |
| `--verbose` | Application debug logging; HTTP wire logging is not enabled |

Filters affect the interesting flag, not raw result retention or authorization
analysis. Network failures have `status_code: null` and an error class; HTTP
errors retain their real status. TLS verification stays enabled. Sessions reuse
connections, ignore environment proxies/netrc, and do not persist server-set
cookies. Set authentication explicitly; interactive login/refresh is unsupported.
Host, framing and proxy-authorization headers cannot be overridden.

Retries use exponential backoff from 0.5s, capped at 8s. Numeric Retry-After is
honored up to 30s; HTTP-date values fall back to backoff. POST/PUT/PATCH/DELETE
are never retried automatically. Selecting these methods also sends random
baseline probes using the same body and can mutate state: use only a suitable
controlled target. There is no automatic concurrency or external target testing.

Wordlists are limited to 4 MiB/10000 unique paths, ID files to 1 MiB, ID expansion
to 10000 values, profiles to 10, and bodies to 1 MiB. Planning checks the request
budget before expanding endpoints. A scan stops before its next request after
8 MiB of retained response prefixes; one final response may exceed that total.
JSON object overhead and transport buffers are additional memory. Stream read
timeouts and between-chunk deadline checks bound ordinary slow responses, but
are not a strict wall-clock deadline against an adversarial trickle server.
Truncated responses have prefix length only, no full hash/JSON, and cannot
produce IDOR findings or act as baselines.

## Body templates

`--data` and `--data-file` send a static UTF-8 body on POST/PUT/PATCH/DELETE.
Set Content-Type yourself. To substitute the path ID inside JSON string values,
create `payload.json` containing `{"resource_id":"{id}"}` and run:

```text
python main.py --base-url http://127.0.0.1:5000 --wordlist wordlists/sample_api.txt --ids 1-2 --methods POST --header "Content-Type: application/json" --data-file payload.json --body-template
```

Substitution uses JSON string-content escaping. Put `{id}` **inside quotes**;
this is not a numeric JSON placeholder, arbitrary JSON field fuzzing, or a
stateful workflow. Without `--body-template`, bodies are sent unchanged.

## Baselines and authorization evidence

Every route template, method and profile gets a random sibling or placeholder
probe. Exact full-body hash, status and content-type matches are suppressed;
404/410 responses are excluded from interesting results. Dynamic fallback
pages, echoed paths, timestamps and numeric-only route converters can limit
baseline effectiveness. A random probe cannot establish the application's
access policy. JSON media types, success/protected/server error statuses,
length differences and keyword boundaries help prioritize endpoint review.

GET IDOR analysis excludes network errors, truncation, baseline matches and
recognized JSON error envelopes, including HTTP 200 errors. It compares bodies,
lengths and owner-like `user_id`/`owner_id` fields within the same profile.
Two different resource IDs or two HTTP 200 responses alone never confirm IDOR.

| Classification | Meaning |
| --- | --- |
| Confirmed Authorization Issue | An explicitly denied profile/ID returns HTTP 200 and a complete body matching another profile explicitly allowed the same route/ID |
| Potential IDOR | Multiple successful IDs within one profile have different bodies, lengths or owner fields; access policy remains unverified; low confidence |
| Inconclusive | Not enough comparable samples or evidence; includes unknown policy, identical bodies, authentication failures and most interrupted checks |
| No Issue Observed | Completed samples of a declared public route succeed, or tested denials are blocked with successful allowed control samples; scoped to those samples |

Confirmed means **against the supplied policy**, not an independent discovery
of business rules. Incorrect policy files produce incorrect conclusions.
Exact response matching is conservative: viewer metadata and dynamic fields can
leave a real lab vulnerability as Potential IDOR. There is no automatic attempt
to bypass authentication, change roles or infer ownership from resource `id`.
401 and 403 counts are recorded separately in per-route assessments.

`examples/profiles.json` uses the lab's Alice/Bob headers and supplies explicit
allow/deny/public rules. Profile files are arrays with `name`, optional `headers`,
`cookie`, and `access`. Each access key is an exact wordlist route template;
`allow`/`deny` contain string IDs, `public` is boolean. Unknown fields and
contradictory rules fail validation. A profiles file cannot be combined with
CLI headers/cookies. Each principal uses an isolated session. Keep real secrets
in an untracked `auth-profiles.local.json` with appropriate filesystem access.
This strict JSON profile configuration is the supported config format; there
is no general scan config loader.

## Reports and exit codes

JSON (`--output`), CSV (`--csv-output`), Markdown (`--md-output`) and standalone
escaped HTML (`--html-output`) are supported. Without any output option, JSON
is written to `reports/report.json`. JSON is the canonical format: complete
request metadata, baselines, summary, findings, route assessments and cancellation
state. CSV is a flat request table; Markdown/HTML include findings and summaries.
CSV cells are protected from spreadsheet formulas. Markdown/HTML escape content.

All display/export paths omit response bodies and previews and redact **every
query value**, including redirect locations. Headers, cookies and request bodies
are never exported. Full-body hashes and owner field names provide evidence
without exporting raw responses. Paths, IDs, profile names, media types and
field names remain visible and may still be sensitive; restrict report access.
Programmatic `run.results` retains bodies in memory for analysis.

Exit codes: 0 completed scan (regardless of findings/network failures), 1 report
write failure, 2 invalid arguments/configuration, 130 interrupted or resource
budget stop. Ctrl+C during scanning closes sessions and exports completed
requests with `cancelled`/`stop_reason`. An in-flight request may be absent from
the partial result. Output files are explicitly selected and overwritten.

## Tests and maintenance

```text
python -m pytest --cov=apifuzz --cov-report=term-missing
python -m ruff check .
python -m ruff format --check .
python -m pip check
python -m pip_audit --local
```

Tests use ephemeral localhost servers only. Dependency auditing queries the
package vulnerability service; it does not scan any API target. CI runs tests,
format/lint and dependency audits. Local package audit skips the unpublished
`apifuzz-lab` project; its code is reviewed and tested here. See `AUDIT_REPORT.md`
for executed checks, fixes, evidence and remaining limitations.

## Troubleshooting and limitations

- Connection refused: start the lab and verify port 5000. Network error classes
  appear separately from HTTP 4xx/5xx; a completed scan can still have errors.
- 401: check authentication. 403: check the principal's authorization. An
  arbitrary custom error envelope still needs manual interpretation.
- TLS errors: use a trusted local certificate; TLS verification cannot be disabled
  with this CLI. Environment proxy and netrc settings are deliberately ignored.
- Budget error: narrow paths/IDs/methods/profiles first; inspect worst-case count.
- Report write failure: choose a writable directory; earlier outputs may already
  have been written. Interrupted filesystem writes are not atomic.
- PowerShell activation policy: invoke `.venv\Scripts\python.exe` directly if
  activation is blocked.
- Public APIs can generate Potential IDOR; declare known public routes in profiles.
- No OpenAPI import, async scanning, generic matching DSL, scan resume, SARIF,
  replay files, automatic token refresh or JSON field mutation is implemented.
  These require further design and are not release claims.
