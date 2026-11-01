from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    1: {"id": 1, "email": "alice@example.test", "role": "user"},
    2: {"id": 2, "email": "bob@example.test", "role": "user"},
    3: {"id": 3, "email": "carol@example.test", "role": "admin"},
}

ORDERS = {
    1: {
        "id": 1,
        "user_id": 1,
        "owner_id": 1,
        "item": "Lab Notebook",
        "invoice": "INV-001",
        "total": 25.0,
    },
    2: {
        "id": 2,
        "user_id": 2,
        "owner_id": 2,
        "item": "Training Token",
        "invoice": "INV-002",
        "total": 99.0,
    },
}


def current_user_id() -> int:
    raw = request.headers.get("X-Lab-User", "1")
    try:
        return int(raw)
    except ValueError:
        return 1


@app.get("/api/users")
def list_users():
    return jsonify({"users": list(USERS.values())})


@app.get("/api/users/<int:user_id>")
def get_user(user_id: int):
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify(user)


@app.get("/api/admin")
def admin_panel():
    if request.headers.get("Authorization") != "Bearer admin-token":
        return jsonify({"error": "admin token required"}), 403
    return jsonify({"status": "ok", "secret": "demo-admin-secret", "role": "admin"})


@app.get("/api/orders/<int:order_id>")
def get_order(order_id: int):
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "order not found"}), 404

    # Vulnerable by design: the lab user can read any order ID.
    # A real app should compare order["owner_id"] with current_user_id().
    viewer = current_user_id()
    response = dict(order)
    response["viewer_user_id"] = viewer
    return jsonify(response)


@app.get("/api/private-orders/<int:order_id>")
def private_order(order_id: int):
    """Control route enforcing both authentication and ownership."""
    raw = request.headers.get("X-Lab-User", "")
    if raw not in {str(user_id) for user_id in USERS}:
        return jsonify({"error": "authentication required"}), 401
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "order not found"}), 404
    if order["owner_id"] != int(raw):
        return jsonify({"error": "not your order"}), 403
    return jsonify(order)


@app.get("/api/health")
def health():
    return jsonify({"status": "healthy"})


@app.get("/api/broken")
def broken():
    return jsonify({"error": "simulated server failure"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
