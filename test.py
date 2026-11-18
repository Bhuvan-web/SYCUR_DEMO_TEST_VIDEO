

"""
Compliance Engine - Intentionally Vulnerable Test Application

PURPOSE:
Test security scanners, AI logic reviewer, RAG retrieval,
and deterministic policy evaluation.

WARNING:
Local testing only. Do not expose this application publicly.
"""

import sqlite3

from flask import (
    Flask,
    request,
    session,
    jsonify,
)
from markupsafe import Markup

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded weak application secret
app.secret_key = "dev-secret-do-not-use"

DB = ":memory:"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER,
            amount REAL
        )
    """)

    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "alice123", "user"),
            (2, "bob", "bob123", "user"),
            (3, "admin", "admin123", "admin"),
        ],
    )

    conn.execute(
        "INSERT INTO invoices VALUES (2001, 2, 5000)"
    )

    conn.commit()
    conn.close()


# --------------------------------------------------
# VULNERABILITY 2: SQL INJECTION
# OWASP WSTG-4.7.5
# --------------------------------------------------

@app.route("/search")
def search_users():

    username = request.args.get("username", "")

    conn = get_db()

    # WRONG: Directly inserting untrusted input into SQL.
    query = (
        f"SELECT id, username FROM users "
        f"WHERE username = '{username}'"
    )

    results = conn.execute(query).fetchall()
    conn.close()

    return jsonify([
        dict(row) for row in results
    ])


# --------------------------------------------------
# VULNERABILITY 3: REFLECTED XSS
# OWASP WSTG-4.7.1
# --------------------------------------------------

@app.route("/greet")
def greet():

    name = request.args.get("name", "Guest")

    # WRONG: Explicitly marking untrusted input as safe HTML.
    html = Markup(f"<h2>Welcome {name}</h2>")

    return str(html)


# --------------------------------------------------
# VULNERABILITY 4: AUTHENTICATION LOGIC BYPASS
# OWASP WSTG-4.4
# --------------------------------------------------

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    # WRONG: Any user with the admin role can bypass
    # password verification.
    if user and (
        user["password"] == password
        or user["role"] == "admin"
    ):

        session["user_id"] = user["id"]
        session["role"] = user["role"]

        return jsonify({
            "message": "Login successful",
            "role": user["role"]
        })

    return jsonify({
        "error": "Invalid credentials"
    }), 401


# --------------------------------------------------
# VULNERABILITY 5: IDOR / BROKEN AUTHORIZATION
# OWASP WSTG-4.5.4
# --------------------------------------------------

@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Authentication required"
        }), 401

    conn = get_db()

    # WRONG: Checks login but never checks invoice ownership.
    invoice = conn.execute(
        "SELECT * FROM invoices WHERE id = ?",
        (invoice_id,)
    ).fetchone()

    conn.close()

    if not invoice:
        return jsonify({
            "error": "Invoice not found"
        }), 404

    return jsonify(dict(invoice))


# --------------------------------------------------
# VULNERABILITY 6: BUSINESS LOGIC / PRICE MANIPULATION
# OWASP WSTG-4.10.1 and WSTG-4.10.2
# --------------------------------------------------

@app.route("/checkout", methods=["POST"])
def checkout():

    if not session.get("user_id"):
        return jsonify({
            "error": "Login required"
        }), 401

    data = request.get_json(silent=True) or {}

    quantity = data.get("quantity", 1)
    unit_price = data.get("unit_price", 100)

    # WRONG:
    # No positive quantity validation.
    # Price is trusted directly from the client.
    total = quantity * unit_price

    return jsonify({
        "quantity": quantity,
        "unit_price": unit_price,
        "total": total,
        "message": "Order processed"
    })


if __name__ == "__main__":

    initialize_database()

    # Localhost only.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
