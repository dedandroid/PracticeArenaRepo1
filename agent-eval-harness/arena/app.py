import json
import os
import re
import sys
import threading
import time
import traceback
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

# `scoring/` is a sibling of this file in the repo, but gets copied to
# /app/scoring alongside app.py inside the arena image (see ../Dockerfile)
# - so it can be a subdirectory of BASE_DIR (in the container) or a
# subdirectory of BASE_DIR's parent (running arena/app.py straight from a
# checkout). Add whichever one actually has it, then import normally.
for _candidate in (BASE_DIR, BASE_DIR.parent):
    if (_candidate / "scoring").is_dir():
        sys.path.insert(0, str(_candidate))
        break

import scoring  # noqa: E402
from scoring.config import PHASE_ORDER, PHASE_WEIGHTS  # noqa: E402
from scoring.log_sensor import evaluate_manifest_against_log  # noqa: E402
from scoring.manifest import Manifest, load_manifests  # noqa: E402
from scoring.run_record import RunRecord  # noqa: E402
from scoring.scorer import band_for, points_gained, s_total  # noqa: E402

LADDER_MANIFEST_DIR = Path(scoring.__file__).resolve().parent / "manifests"

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

# The difficulty-weighted milestone ladder (scoring/) alongside the flat,
# flag-driven milestones above: same challenges, same event logs, a
# different (additive) scoring model - see scoring/manifest.py's docstring.
LADDER_MANIFESTS: dict[str, Manifest] = {m.id: m for m in load_manifests(LADDER_MANIFEST_DIR)}
CHALLENGE_LADDER: dict[str, Manifest] = {
    c["id"]: LADDER_MANIFESTS[c["ladder_manifest"]] for c in CHALLENGES if c.get("ladder_manifest")
}
# challenge_id -> RunRecord, one per challenge with a ladder_manifest.
ladder_runs: dict[str, RunRecord] = {
    challenge_id: RunRecord.blank(manifest) for challenge_id, manifest in CHALLENGE_LADDER.items()
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

    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for event in events:
        for milestone in challenge["milestones"]:
            if cs["milestones"].get(milestone["id"]):
                continue
            if event_matches(milestone["match"], event):
                cs["milestones"][milestone["id"]] = True
    recompute_score(challenge)

    # Same log, evaluated again against this challenge's difficulty-weighted
    # ladder (independent scoring model - see scoring/log_sensor.py).
    run = ladder_runs.get(challenge["id"])
    if run is not None:
        evaluate_manifest_against_log(CHALLENGE_LADDER[challenge["id"]], events, run)


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
    manifest = CHALLENGE_LADDER.get(challenge["id"])
    if manifest is not None:
        ladder_runs[challenge["id"]] = RunRecord.blank(manifest)


def _ladder_view(challenge_id: str) -> dict | None:
    """Milestone-ladder-with-subtasks view for one challenge, in the shape
    the dashboard renders: each phase's weight, whether it's reached, and
    every subtask's own tick state - see scoring/run_record.py."""
    manifest = CHALLENGE_LADDER.get(challenge_id)
    run = ladder_runs.get(challenge_id)
    if manifest is None or run is None:
        return None
    return {
        "difficulty": manifest.difficulty,
        "band": band_for(manifest.difficulty),
        "box_progress": run.box_progress,
        # box_progress * difficulty - this box's comparable contribution to
        # ladder_s_total below (see scoring/scorer.py's points_gained).
        "points_gained": round(points_gained(run, manifest), 4),
        "milestones": [
            {
                "phase": phase,
                "weight": PHASE_WEIGHTS[phase],
                "reached": run.milestones_reached[phase],
                "subtasks": [
                    {"key": s.key, "description": s.description, "done": run.subtasks[phase][s.key]}
                    for s in manifest.milestone(phase).subtasks
                ],
            }
            for phase in PHASE_ORDER
        ],
    }


def build_scorecard() -> dict:
    challenge_scores = {
        c["id"]: {
            "name": c["name"],
            "score": state[c["id"]]["score"],
            "milestones": state[c["id"]]["milestones"],
            "ladder": _ladder_view(c["id"]),
        }
        for c in CHALLENGES
    }
    overall = round(sum(v["score"] for v in challenge_scores.values()) / len(challenge_scores), 2) if challenge_scores else 0.0
    # Difficulty-weighted aggregate across every challenge that has a
    # ladder manifest - see scoring/scorer.py. box_progress itself never
    # includes difficulty; only this cross-box sum does.
    ladder_s_total = s_total(
        [(ladder_runs[cid], manifest) for cid, manifest in CHALLENGE_LADDER.items()]
    )
    return {
        "challenges": challenge_scores,
        "overall_score": overall,
        "ladder_s_total": round(ladder_s_total, 4),
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
                # One challenge's bad config (a malformed milestone/manifest
                # match rule, a bug in a new manifest, etc.) must never take
                # down scoring for every other challenge - this is a daemon
                # thread with no supervisor, so an uncaught exception here
                # silently kills it forever, freezing the entire scoreboard
                # with no visible error short of reading container logs.
                try:
                    evaluate_challenge(challenge)
                except Exception:
                    print(f"[evaluator] error evaluating {challenge['id']!r}:", file=sys.stderr)
                    traceback.print_exc()
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
        write_scorecard()

    # Deliberately just {"correct": bool} - no score, no milestone/ladder
    # state. This is the one endpoint an agent is sanctioned to call, and a
    # score value here is a side-channel: an agent can treat "did the
    # number go up" as a progress oracle instead of actually verifying its
    # own exploitation. Score/milestone visibility stays on /scoreboard,
    # which the agent's brief already puts off-limits.
    return jsonify({"correct": correct})


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
