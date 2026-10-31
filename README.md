# API Endpoint Fuzzer & IDOR Finder

A command-line Python tool for fuzzing API endpoints from a wordlist and
highlighting hidden endpoints, interesting responses, and basic potential IDOR
signals in authorized labs, CTFs, bug bounty scopes, or internal test systems.

## Ethical Usage

Use this tool only on systems you own or have explicit permission to test. It
sets a clear user agent, supports rate limiting and timeouts, and is designed for
learning and authorized security testing. Do not use it against third-party
systems without written authorization.

## Install

```bash
git clone https://github.com/ngduyyy05/ffuf.git
cd ffuf
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux, activate with `source .venv/bin/activate`.

## Wordlist Example

```text
/api/users
/api/users/{id}
/api/admin
/api/orders/{id}
```

`{id}` is replaced with values from `--ids` or `--ids-file`.

## Fuzz Endpoints

```bash
python main.py \
  --base-url http://127.0.0.1:5000 \
  --wordlist wordlists/sample_api.txt \
  --methods GET,POST \
  --ids 1-3 \
  --rate-limit 5 \
  --output reports/report.json \
  --csv-output reports/report.csv \
  --md-output reports/report.md
```

## IDOR Lab Check

```bash
python main.py \
  --base-url http://127.0.0.1:5000 \
  --wordlist wordlists/sample_api.txt \
  --methods GET \
  --ids 1-3 \
  --header "X-Lab-User: 1" \
  --rate-limit 5 \
  --output reports/lab-report.json \
  --md-output reports/lab-report.md
```

You can also pass authentication material:

```bash
python main.py \
  --base-url http://127.0.0.1:5000 \
  --wordlist wordlists/sample_api.txt \
  --methods GET \
  --ids 1-50 \
  --header "Authorization: Bearer test-token" \
  --cookie "session=abc"
```

## Interesting Endpoint Criteria

The analyzer flags responses when it sees:

- HTTP `200`, `201`, `202`, or `204`
- HTTP `401` or `403`, which may indicate an existing protected endpoint
- HTTP `5xx`, which may indicate a server-side error path
- Response length that differs significantly from the baseline 404 response
- JSON media types (`application/json` and `+json`)
- Sensitive-looking response keywords such as `id`, `user`, `email`, `role`,
  `admin`, `token`, `secret`, `order`, or `invoice`

## IDOR Heuristic

Explicit 404/410 responses and responses identical to the method's random-path
baseline are excluded from interesting endpoints. Dynamic fallback pages can
still require manual review. Baselines are collected separately for each method;
the report's `baseline` field retains the first successful baseline for compatibility.

For GET templates such as `/api/users/{id}` or `/api/orders/{id}`, the tool sends
requests for multiple IDs. It marks `Potential IDOR` when several different IDs
return HTTP 200 and the body, length, or owner-like JSON fields (`user_id`,
`owner_id`) differ.

This is a signal, not proof. The tool does not exploit deeper flows or bypass
authorization. A human tester must validate whether access is unauthorized.
Public resources also produce this signal. Resource `id` is not treated as an
owner field. Baseline matches are excluded from IDOR candidate groups.

## Request bodies and input validation

Use `--data` or `--data-file payload.json` for a raw UTF-8 body on
POST/PUT/PATCH/DELETE. Set the appropriate Content-Type yourself:

```bash
python main.py --base-url http://127.0.0.1:5000 --wordlist wordlists/sample_api.txt --ids 1-3 --methods POST --header "Content-Type: application/json" --data-file payload.json
```

Bodies are sent unchanged; `{id}` substitution applies only to wordlist paths.
HEAD is also supported. IDs are URL-encoded as values. Wordlists must contain
relative paths, cannot change the target origin, and are deduplicated. A base
URL path prefix is preserved, so `/users` with base `http://localhost/api/`
requests `http://localhost/api/users`. Redirects are not followed.
Timeout and rate limit must be positive finite values. Rate limiting includes
baseline requests. Templates containing `{id}` require IDs.

Run the regression suite, including a local HTTP lab integration:

```bash
python -m pytest -q
```

## Reports

- Terminal: colored table when `rich` is installed
- JSON: `--output reports/report.json`
- CSV: `--csv-output reports/report.csv`
- Markdown: `--md-output reports/report.md`

## Demo Lab

Run the intentionally vulnerable Flask lab:

```bash
python lab/app.py
```

The lab exposes:

- `/api/users/1`
- `/api/users/2`
- `/api/users/3`
- `/api/admin`
- `/api/orders/1`
- `/api/orders/2`

`/api/orders/<id>` is vulnerable by design because a regular user can view
orders owned by another user by changing the ID.

## Limitations

- The IDOR check is heuristic and can produce false positives.
- It does not understand application-specific authorization models.
- It does not crawl JavaScript, OpenAPI specs, or links.
- Request bodies are static; body fields are not fuzzed yet.
- It is not a replacement for manual testing or scoped methodology.

## Roadmap

- Request body placeholder templates for POST/PUT/PATCH
- OpenAPI import
- Per-route baseline comparison
- Better authentication profiles
- HTML and SARIF report output
- Optional replay files for manual verification
