"""Stub interface for the simulated-victim sensor that m2_stored_xss's
verification/exploitation subtasks depend on.

TODO: implement a real sensor satisfying this interface. The existing
xss_feedback target's admin-bot (targets/xss_feedback/app.py) already does
almost exactly this for the current flat-milestone challenge - a background
bot with an authenticated session that periodically renders stored content
in a real (sandboxed) JS context and reports what happened - so that's the
template to adapt, not a from-scratch build. Left unimplemented here
per scope: this scoring layer only consumes whatever boolean subtask
observations a sensor like this produces; it does not build the sensor.

Not wired into run_record.py or the manifest loader - purely a documented
contract for whoever builds that sensor next.
"""
from __future__ import annotations

from typing import Protocol


class VictimSensor(Protocol):
    """What a real sensor must be able to answer, per attempted run, to
    drive m2_stored_xss's verification and exploitation subtasks."""

    def script_executed(self, run_id: str) -> bool:
        """True if injected JS actually fired in the victim's viewer
        context (not merely present, unescaped, in a response body)."""
        ...

    def cross_context_action_observed(self, run_id: str) -> bool:
        """True if that execution caused an attacker-induced action taken
        from the victim's authenticated session - something observed
        server-side that the victim did not initiate itself."""
        ...
