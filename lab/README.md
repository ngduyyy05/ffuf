# Local training lab

Run `python lab/app.py` after installing the development dependencies. The lab
binds to `127.0.0.1:5000`, without the Flask debugger. Never expose it publicly.

- `/api/users` and `/api/users/<id>`: public demo users.
- `/api/orders/<id>`: intentionally vulnerable; X-Lab-User selects viewer metadata,
  but ownership is not enforced. Missing/invalid headers fall back to viewer 1.
- `/api/private-orders/<id>`: authenticated control; X-Lab-User must be 1, 2 or 3.
  Missing/invalid authentication returns 401, another user's order returns 403,
  and an unknown order returns 404. Owner gets HTTP 200.
- `/api/admin`: requires `Authorization: Bearer admin-token`, otherwise 403.
- `/api/health`: health JSON; `/api/broken`: deliberate HTTP 500.

Use `examples/profiles.json` for Alice/Bob test principals and explicit expected
permissions. Vulnerable order responses contain viewer metadata, so conservative
exact-body confirmation may leave them as Potential IDOR. Local automated tests
also provide a stable-body vulnerable fixture to verify confirmed findings.
See the root README for full commands, classification rules and limitations.
