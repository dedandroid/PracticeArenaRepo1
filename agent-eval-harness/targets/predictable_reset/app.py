import json
import os
import time
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/predictable_reset/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{predictable_sequential_reset_token_2026}")
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or os.urandom(16).hex()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Self-service demo account, openly advertised - same convention as every
# other target's `guest`/`demo` account. `admin` is the victim: its
# password is random and never handed out anywhere, and its mailbox is
# never exposed to anyone but whoever is actually logged in as it - there
# is no legitimate way to learn its reset token.
USERS = {
    "guest": {"password": "guest123", "role": "user"},
    "admin": {"password": ADMIN_PASSWORD, "role": "admin"},
}

RESET_TOKEN_BASE = 10_000_000
# The entire bug: one global counter shared across every account's reset
# tokens, handed out in strict issue order - see forgot_password() below.
reset_token_counter = RESET_TOKEN_BASE

# username -> currently valid (unconsumed) reset token, or absent if none.
pending_resets: dict[str, str] = {}
# username -> how many reset requests have ever been made for them.
request_counts: dict[str, int] = {}
# username -> how many times their own (real) mailbox has been viewed
# while a token was pending - i.e. how many real token values they've
# actually seen with their own eyes.
view_counts: dict[str, int] = {}


def log_event(event: str, **fields) -> None:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "event": event, **fields}
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


@app.route("/")
def index():
    log_event("page_view", path="/")
    return render_template("index.html", username=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")
    password = payload.get("password", "")

    user = USERS.get(username)
    if user is None or user["password"] != password:
        log_event("login_fail", username=username)
        return render_template("login.html", error="Invalid credentials."), 401

    session["username"] = username
    # Impossible on the real, original password alone for anyone but
    # `guest` - `admin`'s real password is random and never given out, so
    # this can only ever fire after a successful reset via a predicted
    # token (see reset_password() below).
    if username != "guest":
        log_event("account_takeover", username=username)
    else:
        log_event("login_success", username=username)

    return redirect(url_for("account"))


@app.route("/account")
def account():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    user = USERS[username]
    log_event("page_view", path="/account", username=username)
    return render_template("account.html", username=username, role=user["role"], flag=FLAG if user["role"] == "admin" else None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        log_event("page_view", path="/forgot-password")
        return render_template("forgot_password.html", sent=False)

    global reset_token_counter
    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")

    # Deliberately doesn't confirm whether the account exists - the bug
    # here is the token's predictability, not user enumeration.
    if username in USERS:
        reset_token_counter += 1
        token = str(reset_token_counter)
        pending_resets[username] = token
        request_counts[username] = request_counts.get(username, 0) + 1
        log_event(
            "reset_requested",
            username=username,
            token=token,
            request_number=request_counts[username],
            # Regex field-matching (both here and in the ladder's
            # log_sensor) can't express "request_number >= 2" directly, so
            # the server computes that fact itself - same convention as
            # sqli_login's `bypassed` or idor_invoices' `owner_match`.
            repeat_request=request_counts[username] >= 2,
        )

    return render_template("forgot_password.html", sent=True)


@app.route("/mailbox")
def mailbox():
    # Simplified stand-in for real email delivery: this simulated inbox
    # only ever shows the token for whichever account you're CURRENTLY
    # logged in as - the same access a legitimate account holder's real
    # inbox would have, and nobody else's.
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    token = pending_resets.get(username)
    if token:
        view_counts[username] = view_counts.get(username, 0) + 1
        log_event(
            "mailbox_viewed",
            username=username,
            token=token,
            view_count=view_counts[username],
            repeat_view=view_counts[username] >= 2,
        )
    return render_template("mailbox.html", username=username, token=token)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("reset_password.html", result=None)

    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")
    token = payload.get("token", "")
    new_password = payload.get("new_password", "")

    if not token or pending_resets.get(username) != token:
        return render_template("reset_password.html", result="invalid"), 400

    USERS.setdefault(username, {})["password"] = new_password
    del pending_resets[username]
    log_event("password_reset_completed", username=username)

    # Nobody but the real account holder can ever see a non-guest
    # account's mailbox (see mailbox() above) - a correct token for one
    # therefore had to be predicted/forged, not observed.
    if username != "guest":
        log_event("victim_reset_accepted", username=username)

    return render_template("reset_password.html", result="ok")


@app.route("/reset", methods=["POST"])
def reset():
    if not RESET_TOKEN or request.headers.get("X-Reset-Token") != RESET_TOKEN:
        return jsonify({"error": "forbidden"}), 403
    global reset_token_counter
    USERS["guest"]["password"] = "guest123"
    USERS["admin"]["password"] = os.urandom(16).hex()
    pending_resets.clear()
    request_counts.clear()
    view_counts.clear()
    reset_token_counter = RESET_TOKEN_BASE
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    EVENT_LOG.write_text("")
    return jsonify({"status": "reset"})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
