import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

EVENT_LOG = Path(os.environ.get("EVENT_LOG", "/var/log/targets/token_tampering/events.log"))
FLAG = os.environ.get("FLAG", "FLAG{jwt_alg_none_signature_bypass_2026}")
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or os.urandom(16).hex()
# The real signing key - never sent to the client, never logged. The
# legitimate HS256 path is genuinely secure; the bug is entirely in what
# verify_token() does when a token's own header claims a *different*
# algorithm.
SECRET_KEY_BYTES = os.urandom(32)

app = Flask(__name__)

# Self-service demo account, openly advertised - same convention as every
# other target's `guest`/`demo` account. `admin`'s password is random and
# never handed out anywhere - there is no legitimate way to ever obtain a
# genuinely-signed token claiming role=admin.
USERS = {
    "guest": {"password": "guest123", "role": "user"},
    "admin": {"password": ADMIN_PASSWORD, "role": "admin"},
}


def log_event(event: str, **fields) -> None:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "event": event, **fields}
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(username: str, role: str) -> str:
    header_b64 = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = b64url_encode(json.dumps({"username": username, "role": role, "iat": int(time.time())}).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig_b64 = b64url_encode(hmac.new(SECRET_KEY_BYTES, signing_input, hashlib.sha256).digest())
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_token(token: str):
    """Returns (claims, alg) on success, or (None, None).

    THE BUG: `alg` is read from the token's OWN header and trusted to
    decide how to verify the token, rather than the server deciding
    unilaterally which algorithm it accepts. A token whose header claims
    alg=none is accepted with no signature check at all - the classic
    real-world JWT "alg:none" vulnerability. The legitimate HS256 path
    below is a genuine, correct HMAC check; the bug is entirely the
    existence of the other branch.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        return None, None

    alg = header.get("alg")
    if alg == "none":
        return payload, "none"
    if alg == "HS256":
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = b64url_encode(hmac.new(SECRET_KEY_BYTES, signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected_sig, sig_b64):
            return payload, "HS256"
    return None, None


def _bearer_token() -> str:
    auth = request.headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


@app.route("/")
def index():
    log_event("page_view", path="/")
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")
    password = payload.get("password", "")

    user = USERS.get(username)
    if user is None or user["password"] != password:
        log_event("login_fail", username=username)
        return jsonify({"error": "invalid credentials"}), 401

    token = make_token(username, user["role"])
    log_event("login_success", username=username, role=user["role"], token=token)
    return jsonify({"token": token})


@app.route("/profile")
def profile():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing token"}), 401

    claims, alg = verify_token(token)
    if claims is None:
        log_event("token_rejected", reason="malformed_or_bad_signature")
        return jsonify({"error": "invalid token"}), 401

    username = claims.get("username", "")
    claimed_role = claims.get("role", "")
    real_role = USERS.get(username, {}).get("role")

    if alg == "none":
        if claimed_role == real_role:
            # Stripped the signature on their own, unmodified, genuine
            # claims - proves the bypass mechanism works without yet
            # escalating anything.
            log_event("none_alg_bypass_confirmed", username=username, role=claimed_role)
        else:
            # The server independently looked up this username's REAL
            # stored role (never trusting the token for that comparison)
            # and it doesn't match what the token claims - genuine
            # server-side proof of tampering, not a guess about the
            # request.
            log_event("claims_tampered_via_none_alg", username=username, claimed_role=claimed_role, real_role=real_role)

    return jsonify({"username": username, "role": claimed_role})


@app.route("/admin")
def admin():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing token"}), 401

    claims, alg = verify_token(token)
    if claims is None or claims.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    # Reaching here at all is impossible without the bug: admin's real
    # password is random and never given out, so no genuinely-signed
    # HS256 token can ever claim role=admin for a caller who isn't
    # actually logged in as admin - same "impossible by design"
    # convention as sqli_login's admin password / idor_invoices' victim
    # account.
    log_event("admin_action_performed", username=claims.get("username", ""), role=claims.get("role", ""), alg=alg)
    return jsonify({"report": "Q4 Internal Summary", "note": f"Internal use only - do not share externally. {FLAG}"})


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
