"""Manifest schema + loader for the difficulty-weighted milestone ladder.

Each manifest is a YAML file (same convention as ../arena/challenges.yaml)
describing one machine: its OWASP category/CWE, its six difficulty-rubric
factor ratings, and its 4-phase subtask ladder.

Integration note (how this consumes the existing evaluator's output): the
arena evaluator (arena/app.py) tails a target's JSON-lines event log and
marks a milestone true the first time one logged event matches an
`{event, field_matches}` rule (see event_matches() there). Each Subtask
below carries an optional `match` in that same shape (or a list of them,
OR-combined, plus an optional `min_count` - see log_sensor.py), reusing the
three targets' *existing* logged events - no target/sensor code was added
to produce them. A subtask with no `match` (see m2_stored_xss.yaml's two
viewer-dependent subtasks) has no real signal available yet and can only
be credited via entailment; see victim_sensor.py. log_sensor.py is what
evaluates these rules against a log and feeds the resulting booleans into
a RunRecord (see run_record.py) - this module only defines the contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import DIFFICULTY_SCALE_CEILING, PHASE_ORDER

DIFFICULTY_FACTOR_NAMES = (
    "discoverability",
    "signal",
    "preconditions",
    "payload",
    "extraction",
    "chain",
)


@dataclass(frozen=True)
class Subtask:
    key: str
    description: str
    # Optional log-matching rule(s) for log_sensor.py: a single
    # {event, field_matches, min_count} dict, a list of such dicts
    # (OR-combined - any one matching is enough), or None if no real signal
    # for this subtask exists yet (it can then only be credited via
    # entailment). Same {event, field_matches} shape as arena/app.py's
    # event_matches() rules, plus an optional min_count (default 1) for
    # subtasks that need a match repeated, e.g. "reproducible".
    match: dict | list[dict] | None = None


@dataclass(frozen=True)
class Milestone:
    """One rung of the 4-phase ladder. `phase` is one of config.PHASE_ORDER;
    its point weight comes from the shared PHASE_WEIGHTS config, not from
    the manifest - weights are constants shared across every machine."""

    phase: str
    subtasks: tuple[Subtask, ...]


@dataclass(frozen=True)
class DifficultyFactors:
    discoverability: int
    signal: int
    preconditions: int
    payload: int
    extraction: int
    chain: int

    def __post_init__(self) -> None:
        for name in DIFFICULTY_FACTOR_NAMES:
            value = getattr(self, name)
            if not (1 <= value <= DIFFICULTY_SCALE_CEILING):
                raise ValueError(
                    f"difficulty factor {name}={value!r} outside 1..{DIFFICULTY_SCALE_CEILING}"
                )

    @property
    def mean(self) -> float:
        return sum(getattr(self, name) for name in DIFFICULTY_FACTOR_NAMES) / len(
            DIFFICULTY_FACTOR_NAMES
        )


@dataclass(frozen=True)
class Manifest:
    id: str
    name: str
    category: str
    cwe: str
    difficulty_factors: DifficultyFactors
    difficulty: float  # = difficulty_factors.mean, computed at load time
    ladder: tuple[Milestone, ...]  # always in PHASE_ORDER order
    victim_sensor_required: bool = False

    def milestone(self, phase: str) -> Milestone:
        for m in self.ladder:
            if m.phase == phase:
                return m
        raise KeyError(phase)


def _load_subtask(raw: dict) -> Subtask:
    return Subtask(key=raw["key"], description=raw["description"], match=raw.get("match"))


def load_manifest(path: str | Path) -> Manifest:
    with open(path) as f:
        raw = yaml.safe_load(f)

    factors = DifficultyFactors(**raw["difficulty_factors"])
    # Difficulty is always derived from the factors, never hand-edited, so
    # the two can never drift apart - but both end up on the loaded
    # Manifest so callers/printouts can show the factors AND the number
    # they produced.
    difficulty = round(factors.mean, 4)

    ladder_by_phase = {entry["phase"]: entry for entry in raw["ladder"]}
    missing = set(PHASE_ORDER) - ladder_by_phase.keys()
    if missing:
        raise ValueError(f"{path}: manifest is missing phases {sorted(missing)}")

    ladder = tuple(
        Milestone(
            phase=phase,
            subtasks=tuple(_load_subtask(s) for s in ladder_by_phase[phase]["subtasks"]),
        )
        for phase in PHASE_ORDER  # enforce canonical order regardless of file order
    )

    return Manifest(
        id=raw["id"],
        name=raw["name"],
        category=raw["category"],
        cwe=raw["cwe"],
        difficulty_factors=factors,
        difficulty=difficulty,
        ladder=ladder,
        victim_sensor_required=bool(raw.get("victim_sensor_required", False)),
    )


def load_manifests(directory: str | Path) -> list[Manifest]:
    directory = Path(directory)
    return [load_manifest(p) for p in sorted(directory.glob("*.yaml"))]
