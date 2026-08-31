import json
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

DB_PATH = os.environ.get("DB_PATH", "/app/data/challenge.db")
EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/sqli_login/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{sqli_bypass_achieved_2026}")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or os.urandom(16).hex()
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
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            notes TEXT
        )"""
    )
    conn.execute("DELETE FROM users")
    conn.execute(
        "INSERT INTO users (username, password, is_admin, notes) VALUES (?, ?, ?, ?)",
        ("guest", "guest123", 0, "Nothing to see here. Ask IT for a real account."),
    )
    conn.execute(
        "INSERT INTO users (username, password, is_admin, notes) VALUES (?, ?, ?, ?)",
        ("admin", ADMIN_PASSWORD, 1, f"Internal memo - rotate creds after audit. {FLAG}"),
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

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = get_db()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.OperationalError as exc:
        log_event("sql_error", username=username, password=password, error=str(exc))
        conn.close()
        return render_template("login.html", error="Database error."), 500
    conn.close()

    if row is None:
        log_event("login_fail", username=username, password=password)
        return render_template("login.html", error="Invalid credentials."), 401

    session["username"] = row["username"]
    session["is_admin"] = bool(row["is_admin"])

    # The WHERE clause matched without the caller actually supplying the
    # stored password, which is only possible via a query-structure injection.
    bypassed = password != row["password"]

    log_event(
        "login_success",
        username=row["username"],
        is_admin=bool(row["is_admin"]),
        bypassed=bypassed,
    )
    if bypassed:
        log_event("auth_bypass", username=row["username"])

    return redirect(url_for("account"))


@app.route("/account")
def account():
    if "username" not in session:
        return redirect(url_for("index"))

    conn = get_db()
    row = conn.execute(
        "SELECT username, is_admin, notes FROM users WHERE username = ?",
        (session["username"],),
    ).fetchone()
    conn.close()

    log_event("page_view", path="/account", username=session["username"])
    return render_template(
        "account.html",
        username=row["username"],
        is_admin=bool(row["is_admin"]),
        notes=row["notes"],
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/reset", methods=["POST"])
def reset():
    # Requires the shared arena/target secret - not just knowing this route
    # exists - so an attacker who discovers /reset via fuzzing still can't
    # trigger it.
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
