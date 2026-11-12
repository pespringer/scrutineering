"""State transitions for operator publication recovery requests."""

from __future__ import annotations


RECOVERY_TRANSITIONS = {
    "requested": frozenset({"acknowledged", "completed", "failed"}),
    "acknowledged": frozenset({"completed", "failed"}),
    "completed": frozenset(),
    "failed": frozenset(),
}


def transition_recovery_status(current: str, target: str) -> str:
    if current == target:
        return current
    if target not in RECOVERY_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid recovery transition: {current} -> {target}")
    return target
