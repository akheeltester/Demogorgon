"""Intentionally Vulnerable App — local E2E testing target.

A minimal Flask app with intentional vulnerabilities:
- IDOR on user profiles (sequential IDs, no authz check)
- IDOR on orders (sequential IDs)
- Open redirect in login
- Reflected XSS in search
- Missing auth on admin endpoint

Start: python -m demogorgon.tests.vulnerable_app
Runs on: http://localhost:5050

This app is for AUTHORIZED TESTING ONLY.
"""

from __future__ import annotations

import json
import time
from functools import wraps

from flask import Flask, request, jsonify, redirect, make_response

app = Flask(__name__)

# ── Data Store ───────────────────────────────────────────────────

USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user", "password": "pass123"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "user", "password": "bob456"},
    3: {"id": 3, "name": "Admin", "email": "admin@example.com", "role": "admin", "password": "admin789"},
}

ORDERS = {
    101: {"id": 101, "user_id": 1, "item": "Widget A", "amount": 29.99, "status": "shipped"},
    102: {"id": 102, "user_id": 2, "item": "Widget B", "amount": 49.99, "status": "processing"},
    103: {"id": 103, "user_id": 1, "item": "Gadget X", "amount": 99.99, "status": "delivered"},
}

SESSIONS: dict[str, int] = {}  # token -> user_id


def get_current_user():
    """Get current user from auth header (simplified)."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = SESSIONS.get(token)
    if user_id:
        return USERS.get(user_id)
    return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request._user = user
        return f(*args, **kwargs)
    return decorated


# ── Auth Endpoints ───────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    """Login and get a session token."""
    data = request.get_json() or {}
    email = data.get("email", "")
    password = data.get("password", "")

    for uid, user in USERS.items():
        if user["email"] == email and user["password"] == password:
            token = f"token_{uid}_{int(time.time())}"
            SESSIONS[token] = uid
            return jsonify({"token": token, "user_id": uid, "name": user["name"]})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    """Logout (invalidate token)."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    SESSIONS.pop(token, None)
    return jsonify({"status": "logged out"})


# ── User Endpoints (IDOR vulnerable) ────────────────────────────

@app.route("/api/users/<int:user_id>")
@require_auth
def get_user(user_id):
    """BUG: No authorization check — any authenticated user can read any profile."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    # BUG: Returns all fields including email and role
    return jsonify(user)


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@require_auth
def update_user(user_id):
    """BUG: No authorization check — any user can update any profile."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    # BUG: Allows role escalation
    for key in ("name", "email", "role"):
        if key in data:
            user[key] = data[key]
    return jsonify(user)


# ── Order Endpoints (IDOR vulnerable) ───────────────────────────

@app.route("/api/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    """BUG: No ownership check — any user can read any order."""
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify(order)


@app.route("/api/orders")
@require_auth
def list_orders():
    """List orders for the current user (this one is correct)."""
    user = request._user
    user_orders = [o for o in ORDERS.values() if o["user_id"] == user["id"]]
    return jsonify({"orders": user_orders})


@app.route("/api/orders", methods=["POST"])
@require_auth
def create_order():
    """Create a new order."""
    data = request.get_json() or {}
    new_id = max(ORDERS.keys()) + 1 if ORDERS else 101
    order = {
        "id": new_id,
        "user_id": request._user["id"],
        "item": data.get("item", "Unknown"),
        "amount": data.get("amount", 0),
        "status": "pending",
    }
    ORDERS[new_id] = order
    return jsonify(order), 201


# ── Admin Endpoint (no auth check) ──────────────────────────────

@app.route("/api/admin/users")
def admin_list_users():
    """BUG: No admin auth check — accessible to anyone."""
    return jsonify({"users": list(USERS.values())})


@app.route("/api/admin/config")
def admin_config():
    """BUG: Exposes internal config — no auth."""
    return jsonify({
        "debug": True,
        "database": "postgresql://admin:secret@db:5432/prod",
        "secret_key": "super-secret-key-12345",
        "api_keys": {"stripe": "sk_live_FAKE", "sendgrid": "SG.FAKE"},
    })


# ── Search (XSS vulnerable) ────────────────────────────────────

@app.route("/api/search")
def search():
    """BUG: Reflected XSS — user input reflected without sanitization."""
    q = request.args.get("q", "")
    # BUG: Directly reflects user input
    return jsonify({
        "query": q,
        "results": [],
        "html": f"<h1>Search results for: {q}</h1>",  # XSS vector
    })


# ── Redirect (Open redirect vulnerable) ─────────────────────────

@app.route("/api/redirect")
def open_redirect():
    """BUG: Unvalidated redirect — open redirect vulnerability."""
    url = request.args.get("url", "/")
    # BUG: No validation of redirect target
    return redirect(url)


# ── Health ───────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})


@app.route("/")
def index():
    return jsonify({
        "name": "Demogorgon Test Target",
        "version": "1.0.0",
        "endpoints": [
            "POST /api/login",
            "POST /api/logout",
            "GET /api/users/<id>",
            "PUT /api/users/<id>",
            "GET /api/orders/<id>",
            "GET /api/orders",
            "POST /api/orders",
            "GET /api/admin/users",
            "GET /api/admin/config",
            "GET /api/search?q=",
            "GET /api/redirect?url=",
            "GET /api/health",
        ],
        "test_credentials": {
            "user_A": {"email": "alice@example.com", "password": "pass123"},
            "user_B": {"email": "bob@example.com", "password": "bob456"},
            "admin": {"email": "admin@example.com", "password": "admin789"},
        },
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  DEMOGORGON TEST TARGET")
    print("  Intentionally Vulnerable Application")
    print("  FOR AUTHORIZED TESTING ONLY")
    print("=" * 50)
    print()
    print("  Endpoints:")
    print("    http://localhost:5050/")
    print("    http://localhost:5050/api/login")
    print("    http://localhost:5050/api/users/<id>")
    print("    http://localhost:5050/api/orders/<id>")
    print("    http://localhost:5050/api/admin/users")
    print("    http://localhost:5050/api/search?q=xss")
    print()
    print("  Test credentials:")
    print("    alice@example.com / pass123")
    print("    bob@example.com / bob456")
    print("    admin@example.com / admin789")
    print()
    app.run(host="127.0.0.1", port=5050, debug=False)
