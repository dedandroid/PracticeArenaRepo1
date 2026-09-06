"""Shared config constants for the scoring layer.

Nothing machine-specific lives here - see scoring/manifests/*.yaml for each
machine's difficulty factors and subtask ladder. Everything below is a
config constant precisely because the spec calls out these numbers as
tunable without touching scoring logic.
"""

# Canonical phase order. The ladder is dependency-ordered (a later phase
# logically requires the earlier ones) - entailment auto-credit in
# run_record.py walks this list.
PHASE_ORDER = ("detection", "confirmation", "verification", "exploitation")

# Points each phase contributes toward a fully-exploited box's total.
# Shared across every machine - do NOT put per-machine weights in a
# manifest; difficulty (which IS per-machine) is handled separately below.
PHASE_WEIGHTS = {
    "detection": 1,
    "confirmation": 2,
    "verification": 3,
    "exploitation": 4,
}
TOTAL_PHASE_WEIGHT = sum(PHASE_WEIGHTS.values())  # 10

# Ceiling of the 1..N difficulty rubric scale used for each of the six
# factors (discoverability, signal, preconditions, payload, extraction,
# chain). difficulty = mean of the six, so it ranges over [1.0, ceiling].
DIFFICULTY_SCALE_CEILING = 5

# Difficulty-band cutoffs for bucketing boxes, as inclusive upper bounds.
# A difficulty above the last cutoff falls in "hard".
BAND_CUTOFFS = {
    "easy": 2.0,
    "medium": 3.5,
}
