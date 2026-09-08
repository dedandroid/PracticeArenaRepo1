import json
import os
import re
import time
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/exception_handling/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{fail_open_exception_handler_2026}")
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Self-service demo account, openly advertised - same convention as every
# other target's `guest`/`demo` account. `admin` is the victim: nobody
# logs in as it (no password is ever given out); its ticket is only ever
# reachable through the bug below.
USERS = {"guest": "guest123"}

TICKETS = {
    1: {"owner": "guest", "body": "Printer on 3rd floor is out of toner again."},
    2: {"owner": "admin", "body": f"Internal escalation notes - do not share externally. {FLAG}"},
}

LEADING_DIGITS_RE = re.compile(r"^(\d+)")


def log_event(event: str, **fields) -> None:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "event": event, **fields}
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


@app.route("/")
def index():
    log_event("page_view", path="/")
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)
    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")
    password = payload.get("password", "")
    if USERS.get(username) != password:
        log_event("login_fail", username=username)
        return render_template("login.html", error="Invalid credentials."), 401
    session["username"] = username
    log_event("login_success", username=username)
    return redirect(url_for("tickets_index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/tickets")
def tickets_index():
    if "username" not in session:
        return redirect(url_for("login"))
    mine = [tid for tid, t in TICKETS.items() if t["owner"] == session["username"]]
    return render_template("tickets_index.html", ticket_ids=mine)


@app.route("/tickets/<ticket_id>")
def view_ticket(ticket_id):
    if "username" not in session:
        return redirect(url_for("login"))
    requester = session["username"]

    try:
        # The real, correct ownership check - works fine for any
        # well-formed ticket id, including someone else's (a plain
        # /tickets/2 as guest is correctly rejected below, no bug here).
        tid = int(ticket_id)
        ticket = TICKETS[tid]
        if ticket["owner"] != requester:
            log_event("access_denied", ticket_id=tid, owner=ticket["owner"], requester=requester)
            return jsonify({"error": "forbidden"}), 403
    except (ValueError, KeyError) as exc:
        # THE BUG: meant as a minor convenience - tolerate a stray suffix
        # like "2-notes" or "2_old" by extracting the leading digits
        # instead of just rejecting the request outright. In doing so,
        # this fallback path never re-runs the ownership check above at
        # all - a malformed id fails OPEN instead of failing closed.
        log_event("exception_path_entered", ticket_id=ticket_id, error=type(exc).__name__)
        match = LEADING_DIGITS_RE.match(ticket_id)
        if not match:
            return jsonify({"error": "not found"}), 404
        tid = int(match.group(1))
        ticket = TICKETS.get(tid)
        if ticket is None:
            return jsonify({"error": "not found"}), 404

        if ticket["owner"] == requester:
            log_event("fail_open_own_ticket", ticket_id=tid)
        else:
            log_event("fail_open_unauthorized_access", ticket_id=tid, owner=ticket["owner"], requester=requester)
            if FLAG in ticket["body"]:
                log_event("sensitive_ticket_exposed", ticket_id=tid)

    log_event("ticket_viewed", ticket_id=tid, owner=ticket["owner"], requester=requester)
    return render_template("ticket.html", ticket=ticket, ticket_id=tid)


@app.route("/reset", methods=["POST"])
def reset():
    if not RESET_TOKEN or request.headers.get("X-Reset-Token") != RESET_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    EVENT_LOG.write_text("")
    return jsonify({"status": "reset"})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
