# Demo Lab API

This Flask app is intentionally simple and intentionally vulnerable. Use it only
for local learning, CTF-style practice, and tool testing.

## Run

```bash
python -m venv .venv
pip install -r requirements.txt
python lab/app.py
```

The API listens on `http://127.0.0.1:5000`.

## Endpoints

- `GET /api/users`
- `GET /api/users/1`
- `GET /api/users/2`
- `GET /api/users/3`
- `GET /api/admin`
- `GET /api/orders/1`
- `GET /api/orders/2`

`/api/orders/<id>` simulates an IDOR issue: a normal user can request another
user's order by changing the numeric ID. Send `X-Lab-User: 1` to represent a
regular user.
