"""Demo/test for the scoring layer: feeds simulated runs through every
manifest and prints the checklist state, milestones reached, and
box_progress for each, then the difficulty-weighted S_total across boxes
and each box's difficulty band.

This simulates what a sensor/evaluator would eventually feed in (booleans
per subtask) - no target, sensor, or victim browser is involved. Run with:

    python -m scoring.demo
"""
from __future__ import annotations

from pathlib import Path

from .config import PHASE_ORDER
from .manifest import Manifest, load_manifests
from .run_record import RunRecord, recompute
from .scorer import band_for, box_progress, s_total

MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"


def _mark_all(run: RunRecord, manifest: Manifest, phase: str) -> None:
    for subtask in manifest.milestone(phase).subtasks:
        run.mark_subtask(phase, subtask.key)


def simulate_stalled_at_detection(manifest: Manifest) -> RunRecord:
    """Agent found the bug but never got further."""
    run = RunRecord.blank(manifest)
    _mark_all(run, manifest, "detection")
    recompute(run, manifest)
    return run


def simulate_verified_only(manifest: Manifest) -> RunRecord:
    """Agent proved the injection/bypass executes, but never reached
    protected data."""
    run = RunRecord.blank(manifest)
    for phase in ("detection", "confirmation", "verification"):
        _mark_all(run, manifest, phase)
    recompute(run, manifest)
    return run


def simulate_fully_exploited(manifest: Manifest) -> RunRecord:
    """Agent rode the ladder all the way to exploitation."""
    run = RunRecord.blank(manifest)
    for phase in PHASE_ORDER:
        _mark_all(run, manifest, phase)
    recompute(run, manifest)
    return run


def simulate_entailment_only(manifest: Manifest) -> RunRecord:
    """Exploitation fires while detection's own subtasks were NEVER logged -
    proves entailment auto-credits detection (and every phase in between)
    anyway, since exploitation logically implies it happened."""
    run = RunRecord.blank(manifest)
    for phase in ("confirmation", "verification", "exploitation"):
        _mark_all(run, manifest, phase)
    # detection subtasks deliberately left False/unobserved
    recompute(run, manifest)
    return run


def _print_run(label: str, manifest: Manifest, run: RunRecord) -> None:
    print(f"  [{label}]")
    for phase in PHASE_ORDER:
        checklist = ", ".join(f"{k}={v}" for k, v in run.subtasks[phase].items())
        reached = run.milestones_reached[phase]
        print(f"    {phase:<13} reached={reached!s:<5} subtasks: {checklist}")
    print(f"    box_progress = {run.box_progress}")


def main() -> None:
    manifests = load_manifests(MANIFEST_DIR)
    assert len(manifests) == 8, f"expected 8 manifests, found {len(manifests)}"

    fully_exploited_runs: list[tuple[RunRecord, Manifest]] = []

    for manifest in manifests:
        print(f"\n=== {manifest.id} - {manifest.name} ({manifest.category}, {manifest.cwe}) ===")
        print(f"  difficulty factors: {manifest.difficulty_factors}")
        print(f"  difficulty = {manifest.difficulty}  band = {band_for(manifest.difficulty)}")

        stalled = simulate_stalled_at_detection(manifest)
        _print_run("stalled at detection", manifest, stalled)
        assert stalled.box_progress == 1 / 10

        verified = simulate_verified_only(manifest)
        _print_run("verification-only", manifest, verified)
        assert verified.box_progress == 0.6, verified.box_progress

        exploited = simulate_fully_exploited(manifest)
        _print_run("fully exploited", manifest, exploited)
        assert exploited.box_progress == 1.0, exploited.box_progress
        fully_exploited_runs.append((exploited, manifest))

    # Entailment proof: run it once, on M1, per the spec's single extra
    # demonstration run. The same logic applies identically to M2/M3.
    m1 = next(m for m in manifests if m.id == "m1_sqli_login")
    print(f"\n=== entailment proof ({m1.id}) ===")
    entailed = simulate_entailment_only(m1)
    _print_run("exploitation fired, detection subtasks never logged", m1, entailed)
    assert entailed.milestones_reached["detection"] is True, "entailment should have auto-credited detection"
    assert all(v is False for v in entailed.subtasks["detection"].values()), (
        "detection's own subtasks should remain unobserved - only the milestone is entailed"
    )
    assert entailed.box_progress == 1.0

    total = s_total(fully_exploited_runs)
    print(f"\nS_total (all boxes fully exploited) = {total}")
    # Every box is fully exploited (box_progress == 1.0), so S_total should
    # equal the plain sum of every manifest's difficulty - self-checking
    # rather than a hand-maintained magic number that would need updating
    # every time a machine is added.
    expected = sum(m.difficulty for m in manifests)
    assert abs(total - expected) < 1e-9, (total, expected)

    print("\nAll assertions passed.")


if __name__ == "__main__":
    main()
