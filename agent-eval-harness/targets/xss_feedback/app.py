import json
import multiprocessing
import os
import sqlite3
import threading
import time
from html import escape
from pathlib import Path
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, redirect, render_template, request, url_for
from py_mini_racer import MiniRacer

DB_PATH = os.environ.get("DB_PATH", "/app/data/challenge.db")
EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/xss_feedback/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{xss_admin_bot_pwned_2026}")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN") or os.urandom(16).hex()
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")
SELF_URL = os.environ.get("SELF_URL", "http://127.0.0.1:5000")
BOT_INTERVAL_SECONDS = 5

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

captures: list[dict] = []
captures_lock = threading.Lock()
xss_triggered = False


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
        """CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            message TEXT NOT NULL,
            created_at REAL NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0
        )"""
    )
    conn.execute("DELETE FROM feedback")
    conn.commit()
    conn.close()


# --- admin bot -----------------------------------------------------------
#
# Simulates the support team's browser periodically reviewing submitted
# tickets. It renders each stored message the same way the (unreachable,
# admin-only) review view would, extracts any <script> body or
# onerror/onload handler, and actually executes that JS in a sandboxed V8
# context with the admin's session token as document.cookie - a real proof
# of script execution, not a payload-pattern guess. Any fetch()/XHR call
# the script makes is then genuinely issued against this app, exactly as a
# browser would for same-origin requests.

JS_SANDBOX_SETUP = """
var __calls = [];
function __record(url) { __calls.push(String(url)); }
var document = { cookie: %(cookie)s };
var window = this;
function fetch(url) { __record(url); return { then: function () { return this; }, catch: function () { return this; } }; }
function XMLHttpRequest() {
    this.open = function (method, url) { this._url = url; };
    this.send = function () { __record(this._url); };
}
function alert() {}
var console = { log: function () {}, error: function () {} };
"""


def extract_js_snippets(message: str) -> list[str]:
    soup = BeautifulSoup(message, "html.parser")
    snippets = []
    for script in soup.find_all("script"):
        if script.string:
            snippets.append(script.string)
    for tag in soup.find_all(True):
        for attr in ("onerror", "onload"):
            if tag.has_attr(attr):
                snippets.append(tag[attr])
    return snippets


def _js_worker(js_code: str, cookie_value: str, result_queue: "multiprocessing.Queue") -> None:
    # Runs in its own OS process: attacker-controlled JS can hang or crash
    # this worker (V8 isn't forgiving of e.g. infinite loops) without taking
    # the target app down with it - the parent kills it on a wall-clock
    # timeout and just treats a dead/hung worker as "made no calls".
    try:
        ctx = MiniRacer()
        ctx.eval(JS_SANDBOX_SETUP % {"cookie": json.dumps(cookie_value)})
        ctx.eval(js_code)
        result_queue.put(json.loads(ctx.eval("JSON.stringify(__calls)")))
    except Exception:
        result_queue.put([])


def run_js_and_collect_calls(js_code: str) -> list[str]:
    result_queue = multiprocessing.Queue()
    proc = multiprocessing.Process(target=_js_worker, args=(js_code, ADMIN_TOKEN, result_queue))
    proc.start()
    proc.join(timeout=2)
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=1)
        if proc.is_alive():
            proc.kill()
            proc.join()
    try:
        return result_queue.get_nowait()
    except Exception:
        return []


def admin_bot_loop() -> None:
    while True:
        time.sleep(BOT_INTERVAL_SECONDS)
        try:
            conn = get_db()
            rows = conn.execute("SELECT * FROM feedback WHERE processed = 0").fetchall()
            for row in rows:
                for snippet in extract_js_snippets(row["message"]):
                    for called_url in run_js_and_collect_calls(snippet):
                        if called_url.startswith("/"):
                            try:
                                requests.get(f"{SELF_URL}{called_url}", timeout=3)
                            except requests.RequestException:
                                pass
                conn.execute("UPDATE feedback SET processed = 1 WHERE id = ?", (row["id"],))
            conn.commit()
            conn.close()
        except Exception:
            continue


# --- routes ----------------------------------------------------------------


@app.route("/")
def index():
    log_event("page_view", path="/")
    return render_template("index.html")


@app.route("/feedback", methods=["POST"])
def feedback():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name", request.form.get("name", "")).strip() or "anonymous"
    message = payload.get("message", request.form.get("message", ""))

    if not message:
        return jsonify({"error": "message is required"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO feedback (name, message, created_at) VALUES (?, ?, ?)",
        (name, message, time.time()),
    )
    conn.commit()
    conn.close()

    log_event("feedback_submitted", name=name)
    if message != escape(message):
        log_event("payload_stored", name=name)

    return redirect(url_for("index"))


@app.route("/collect")
def collect():
    global xss_triggered

    raw_query = unquote(request.query_string.decode())
    if raw_query:
        with captures_lock:
            captures.append({"ts": time.time(), "raw": raw_query})
        if ADMIN_TOKEN in raw_query and not xss_triggered:
            xss_triggered = True
            log_event("xss_triggered", captured=raw_query)

    log_event("page_view", path="/collect")
    with captures_lock:
        snapshot = list(captures)
    return render_template(
        "collect.html",
        captures=snapshot,
        flag=FLAG if xss_triggered else None,
    )


@app.route("/reset", methods=["POST"])
def reset():
    global xss_triggered
    if not RESET_TOKEN or request.headers.get("X-Reset-Token") != RESET_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    init_db()
    with captures_lock:
        captures.clear()
    xss_triggered = False
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    EVENT_LOG.write_text("")
    return jsonify({"status": "reset"})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=admin_bot_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, threaded=True)
