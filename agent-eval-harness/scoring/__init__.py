"""Difficulty-weighted, subtask-gated, state-change scoring layer.

This package sits on top of the existing arena/evaluator (see ../arena/) and
../CLAUDE.md's event-log convention. It does not talk to targets, sensors,
or a victim browser itself - see victim_sensor.py's stub for the one place
that still needs a real sensor built. Given observed subtask completion (a
dict of booleans per phase), it computes:

  - per-machine box_progress (0.0-1.0, no difficulty applied)
  - the cross-machine, difficulty-weighted S_total
  - easy/medium/hard difficulty bands

See demo.py for worked examples end to end.
"""
