import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
CHALLENGES_PATH = BASE_DIR / "challenges.yaml"
LOG_DIR = Path(os.environ.get("SHARED_LOG_DIR", "/var/log/targets"))
RUN_DIR = Path(os.environ.get("RUN_DIR", "/runs/current"))
RUN_DIR.mkdir(parents=True, exist_ok=True)
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")

app = Flask(__name__)
state_lock = threading.Lock()


def load_challenges() -> list[dict]:
    with open(CHALLENGES_PATH) as f:
        return yaml.safe_load(f)["challenges"]


CHALLENGES = load_challenges()
CHALLENGES_BY_ID = {c["id"]: c for c in CHALLENGES}

# challenge_id -> {"milestones": {milestone_id: bool}, "score": float}
state: dict[str, dict] = {
    c["id"]: {"milestones": {m["id"]: False for m in c["milestones"]}, "score": 0.0}
    for c in CHALLENGES
}


def event_matches(rule: dict, event: dict) -> bool:
    if "event" in rule and event.get("event") != rule["event"]:
        return False
    for field, pattern in rule.get("field_matches", {}).items():
        if not re.search(pattern, str(event.get(field, "")), re.IGNORECASE):
            return False
    return True


def recompute_score(challenge: dict) -> None:
    cs = state[challenge["id"]]
    total_weight = sum(m["weight"] for m in challenge["milestones"])
    earned = sum(m["weight"] for m in challenge["milestones"] if cs["milestones"].get(m["id"]))
    cs["score"] = round(100 * earned / total_weight, 2) if total_weight else 0.0


def evaluate_challenge(challenge: dict) -> None:
    log_path = LOG_DIR / challenge["log_file"]
    if not log_path.exists():
        return
    cs = state[challenge["id"]]
    with open(log_path) as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        for milestone in challenge["milestones"]:
            if cs["milestones"].get(milestone["id"]):
                continue
            if event_matches(milestone["match"], event):
                cs["milestones"][milestone["id"]] = True
    recompute_score(challenge)


def reset_challenge(challenge: dict) -> None:
    """Reset one challenge's target state and evaluator state (caller holds state_lock)."""
    internal_url = challenge.get("internal_url")
    if internal_url:
        try:
            req = urllib.request.Request(
                f"{internal_url}/reset",
                method="POST",
                headers={"X-Reset-Token": RESET_TOKEN},
            )
            urllib.request.urlopen(req, timeout=5)
        except (urllib.error.URLError, OSError):
            pass  # target may be mid-restart; evaluator state resets regardless
    state[challenge["id"]] = {
        "milestones": {m["id"]: False for m in challenge["milestones"]},
        "score": 0.0,
    }


def build_scorecard() -> dict:
    challenge_scores = {
        c["id"]: {
            "name": c["name"],
            "score": state[c["id"]]["score"],
            "milestones": state[c["id"]]["milestones"],
        }
        for c in CHALLENGES
    }
    overall = round(sum(v["score"] for v in challenge_scores.values()) / len(challenge_scores), 2) if challenge_scores else 0.0
    return {
        "challenges": challenge_scores,
        "overall_score": overall,
        "updated_at": time.time(),
    }


def write_scorecard() -> dict:
    scorecard = build_scorecard()
    with open(RUN_DIR / "scorecard.json", "w") as f:
        json.dump(scorecard, f, indent=2)
    return scorecard


def evaluator_loop() -> None:
    while True:
        with state_lock:
            for challenge in CHALLENGES:
                evaluate_challenge(challenge)
            write_scorecard()
        time.sleep(1)


threading.Thread(target=evaluator_loop, daemon=True).start()


@app.route("/")
def index():
    return render_template("index.html", challenges=CHALLENGES)


@app.route("/scoreboard")
def scoreboard():
    with state_lock:
        return jsonify(build_scorecard())


@app.route("/api/targets")
def list_targets():
    """Minimal id lookup for an attacking agent: just enough (id + the URL
    it's already attacking) to know what to submit a flag against - no
    name, milestones, or score. Generic over challenges.yaml, so a new
    challenge needs no changes here."""
    return jsonify([{"id": c["id"], "target_url": c["target_url"]} for c in CHALLENGES])


@app.route("/api/challenges/<challenge_id>/flag", methods=["POST"])
def submit_flag(challenge_id: str):
    challenge = CHALLENGES_BY_ID.get(challenge_id)
    if not challenge:
        return jsonify({"error": "unknown challenge"}), 404

    payload = request.get_json(silent=True) or request.form
    submitted = str(payload.get("flag", "")).strip()
    expected = os.environ.get(challenge["flag_env_var"], "")
    correct = bool(expected) and submitted == expected

    with state_lock:
        cs = state[challenge_id]
        if correct:
            cs["milestones"]["flag_submitted"] = True
            recompute_score(challenge)
        scorecard = write_scorecard()

    return jsonify({"correct": correct, "score": scorecard["challenges"][challenge_id]["score"]})


@app.route("/api/challenges/<challenge_id>/reset", methods=["POST"])
def reset_one(challenge_id: str):
    challenge = CHALLENGES_BY_ID.get(challenge_id)
    if not challenge:
        return jsonify({"error": "unknown challenge"}), 404

    with state_lock:
        reset_challenge(challenge)
        scorecard = write_scorecard()

    return jsonify(scorecard)


@app.route("/api/reset", methods=["POST"])
def reset_all():
    with state_lock:
        for challenge in CHALLENGES:
            reset_challenge(challenge)
        scorecard = write_scorecard()

    return jsonify(scorecard)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
