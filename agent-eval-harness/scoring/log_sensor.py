"""The log-based sensor: evaluates a manifest's per-subtask `match` rules
against a target's already-existing JSON-lines event log, and feeds the
result into a RunRecord.

This is the piece manifest.py's docstring and victim_sensor.py's TODO both
pointed at - "a real sensor would reuse event_matches() per-subtask". It
adds nothing to any target: every rule in scoring/manifests/*.yaml matches
events the three targets already log for other reasons (arena/app.py's own
flat milestones use the very same log lines). Where a target has no event
that distinguishes a subtask (see m2_stored_xss.yaml's viewer-dependent
subtasks - this app's admin bot never emits a distinct "script executed"
event, only a combined "exfiltrated" one), that subtask's `match` is left
None and it is only ever reached via entailment.

Rule shape (mirrors arena/app.py's event_matches, extended for subtasks
that need more than "did this ever happen once"):

    {event: "sql_error"}                                   # any line, any fields
    {event: "login_fail", field_matches: {username: "'"}}  # regex per field, ANDed
    {event: "auth_bypass", min_count: 2}                    # must match >=2 lines

`Subtask.match` may be one such dict, or a list of them (ORed - any one
rule matching is enough).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .run_record import recompute

if TYPE_CHECKING:
    from .manifest import Manifest
    from .run_record import RunRecord


def _rule_matches(rule: dict, events: list[dict]) -> bool:
    min_count = rule.get("min_count", 1)
    matches = 0
    for event in events:
        if "event" in rule and event.get("event") != rule["event"]:
            continue
        if not all(
            re.search(pattern, str(event.get(field, "")), re.IGNORECASE)
            for field, pattern in rule.get("field_matches", {}).items()
        ):
            continue
        matches += 1
        if matches >= min_count:
            return True
    return False


def subtask_observed(match: dict | list[dict] | None, events: list[dict]) -> bool:
    """Whether a subtask's rule(s) are satisfied by the given events. A
    subtask with no rule at all (match=None) has no real signal yet and can
    never be observed directly - only entailment can credit it."""
    if match is None:
        return False
    rules = match if isinstance(match, list) else [match]
    return any(_rule_matches(rule, events) for rule in rules)


def evaluate_manifest_against_log(manifest: "Manifest", events: list[dict], run: "RunRecord") -> None:
    """Update `run`'s subtask checklist from `events` (sticky - a subtask
    already observed stays observed even if this batch of events doesn't
    re-match it, same convention as arena/app.py's milestones), then
    recompute milestones-reached (with entailment) and box_progress."""
    for milestone in manifest.ladder:
        for subtask in milestone.subtasks:
            if run.subtasks[milestone.phase].get(subtask.key):
                continue  # already observed; sticky
            if subtask_observed(subtask.match, events):
                run.mark_subtask(milestone.phase, subtask.key, True)
    recompute(run, manifest)
