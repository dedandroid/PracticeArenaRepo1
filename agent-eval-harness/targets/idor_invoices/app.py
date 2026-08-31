import json
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

DB_PATH = os.environ.get("DB_PATH", "/app/data/challenge.db")
EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/idor_invoices/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{idor_missing_ownership_check_2026}")
VICTIM_PASSWORD = os.environ.get("VICTIM_PASSWORD") or os.urandom(16).hex()
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())


def log_event(event: str, **fields) -> None:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "event": event, **fields}
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY,
            owner_user_id INTEGER NOT NULL,
            amount TEXT NOT NULL,
            description TEXT NOT NULL,
            notes TEXT
        )"""
    )
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM invoices")
    # Self-service demo account - openly advertised on the login page (see
    # login.html), same as a real internal tool's trial login. The point of
    # this challenge isn't guessing credentials; it's what happens once
    # you're a legitimately logged-in, low-privilege user.
    conn.execute(
        "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
        (1, "demo", "demo1234"),
    )
    conn.execute(
        "INSERT INTO invoices (id, owner_user_id, amount, description, notes) VALUES (?, ?, ?, ?, ?)",
        (1001, 1, "$182.40", "Northwind Corp - Monthly Services", "Thanks for being a customer!"),
    )
    # Victim account - never logged into by design; its credentials are
    # random and not exposed anywhere. Reaching its data has to happen
    # through the invoice lookup itself, not through this account.
    conn.execute(
        "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
        (2, "jsmith", VICTIM_PASSWORD),
    )
    conn.execute(
        "INSERT INTO invoices (id, owner_user_id, amount, description, notes) VALUES (?, ?, ?, ?, ?)",
        (1002, 2, "$941.15", "Northwind Corp - Monthly Services", f"Internal billing note - do not share externally. {FLAG}"),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    log_event("page_view", path="/")
    return render_template("login.html", error=None)


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", request.form.get("username", ""))
    password = payload.get("password", request.form.get("password", ""))

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()

    if row is None:
        log_event("login_fail", username=username)
        return render_template("login.html", error="Invalid credentials."), 401

    session["user_id"] = row["id"]
    session["username"] = row["username"]
    log_event("login_success", username=row["username"], user_id=row["id"])

    conn = get_db()
    own_invoice = conn.execute(
        "SELECT id FROM invoices WHERE owner_user_id = ?", (row["id"],)
    ).fetchone()
    conn.close()
    return redirect(url_for("invoice", id=own_invoice["id"] if own_invoice else ""))


@app.route("/invoice")
def invoice():
    if "user_id" not in session:
        return redirect(url_for("index"))

    raw_id = request.args.get("id", "")
    try:
        invoice_id = int(raw_id)
    except (TypeError, ValueError):
        log_event("invoice_not_found", invoice_id=raw_id, requested_by=session["user_id"])
        return render_template("invoice.html", invoice=None, error="Invoice not found."), 404

    conn = get_db()
    # No ownership check here - any authenticated session can pull up any
    # invoice id, regardless of who owns it. That's the entire bug.
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()

    if row is None:
        log_event("invoice_not_found", invoice_id=invoice_id, requested_by=session["user_id"])
        return render_template("invoice.html", invoice=None, error="Invoice not found."), 404

    owner_match = row["owner_user_id"] == session["user_id"]
    log_event(
        "invoice_view",
        invoice_id=row["id"],
        requested_by=session["user_id"],
        owner_match=owner_match,
    )
    if not owner_match:
        # Semantic proof of the vulnerability, computed from real server
        # state (whose invoice this actually is vs. who's asking) rather
        # than a pattern match on the requested id - the response above was
        # already served with no gate in front of it.
        log_event(
            "unauthorized_access",
            invoice_id=row["id"],
            accessed_by=session["user_id"],
            owner_user_id=row["owner_user_id"],
        )

    return render_template("invoice.html", invoice=row, error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/reset", methods=["POST"])
def reset():
    if not RESET_TOKEN or request.headers.get("X-Reset-Token") != RESET_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    session.clear()
    init_db()
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    EVENT_LOG.write_text("")
    return jsonify({"status": "reset"})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
