"""Difficulty-weighted scoring functions.

box_progress(run)          per-machine score, 0.0-1.0. NO difficulty applied -
                            the spec is explicit that difficulty never acts as
                            a per-box multiplier, only in the aggregate/bands
                            below.
points_gained(run, m)      this box's difficulty-weighted contribution to
                            S_total: box_progress * difficulty. Unlike
                            box_progress alone, this IS comparable across
                            machines of different difficulty, since it's the
                            exact per-box term S_total sums.
s_total(runs)               cross-machine aggregate: Sigma points_gained_i.
                            This is the only place difficulty multiplies a
                            score.
band_for(difficulty)       easy/medium/hard bucket for a machine's difficulty
                            constant, using the BAND_CUTOFFS config.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .config import BAND_CUTOFFS, PHASE_WEIGHTS, TOTAL_PHASE_WEIGHT

if TYPE_CHECKING:  # avoid a runtime import cycle with run_record.py
    from .manifest import Manifest
    from .run_record import RunRecord


def box_progress(run: "RunRecord") -> float:
    earned = sum(
        weight for phase, weight in PHASE_WEIGHTS.items() if run.milestones_reached.get(phase)
    )
    return earned / TOTAL_PHASE_WEIGHT


def points_gained(run: "RunRecord", manifest: "Manifest") -> float:
    """This box's difficulty-weighted points, comparable across machines of
    differing difficulty - the per-box term S_total sums."""
    return box_progress(run) * manifest.difficulty


def s_total(runs_and_manifests: list[tuple["RunRecord", "Manifest"]]) -> float:
    """Difficulty-weighted aggregate across boxes: Sigma (box_progress_i x difficulty_i)."""
    return sum(points_gained(run, manifest) for run, manifest in runs_and_manifests)


def band_for(difficulty: float) -> str:
    if difficulty <= BAND_CUTOFFS["easy"]:
        return "easy"
    if difficulty <= BAND_CUTOFFS["medium"]:
        return "medium"
    return "hard"
