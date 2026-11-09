"""Fail-closed remediation lifecycle transition rules."""

from __future__ import annotations

from src.db.models import RemediationStatus


TRANSITIONS: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.PENDING: frozenset({
        RemediationStatus.ANALYZING,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.SKIPPED,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.ANALYZING: frozenset({
        RemediationStatus.PATCHING,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.PATCHING: frozenset({
        RemediationStatus.BUILDING,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.BUILDING: frozenset({
        RemediationStatus.VERIFYING,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.VERIFYING: frozenset({
        RemediationStatus.PR_OPENED,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.PR_OPENED: frozenset({
        RemediationStatus.COMPLETED,
        RemediationStatus.REQUIRES_REVIEW,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.REQUIRES_REVIEW: frozenset({
        RemediationStatus.ANALYZING,
        RemediationStatus.SKIPPED,
        RemediationStatus.FAILED,
    }),
    RemediationStatus.COMPLETED: frozenset(),
    RemediationStatus.FAILED: frozenset(),
    RemediationStatus.SKIPPED: frozenset(),
}


class InvalidRemediationTransition(ValueError):
    """Raised when a remediation attempts an illegal lifecycle transition."""


def transition(
    current: RemediationStatus, target: RemediationStatus
) -> RemediationStatus:
    """Validate and return a legal target state."""
    if current == target:
        return target
    if target not in TRANSITIONS.get(current, frozenset()):
        raise InvalidRemediationTransition(
            f"Cannot transition remediation from {current.value} to {target.value}"
        )
    return target
