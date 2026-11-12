"""State transitions for operator publication recovery requests."""

from __future__ import annotations

from datetime import timedelta


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


def retry_delay_seconds(attempt: int, *, base: int = 15, maximum: int = 300) -> int:
    """Return bounded exponential backoff after an attempt (1-based)."""
    if attempt < 1:
        raise ValueError("attempt must be positive")
    return min(maximum, base * (2 ** (attempt - 1)))


def retry_at(now, attempt: int):
    return now + timedelta(seconds=retry_delay_seconds(attempt))
