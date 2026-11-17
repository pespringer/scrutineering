"""The remediation lifecycle: the only place that says which status may follow which.

    proposed ──approve──▶ approved ──execute──▶ building ──▶ verifying ──┬──▶ ready ──rescan clean──▶ completed
                                                                        └──▶ needs_acceptance ──accept──▶ ready
    ready ──publish──▶ published ──merged, rebuilt image rescanned clean──▶ completed
    any non-terminal state ──cancel──▶ cancelled
    building / verifying / published ──▶ failed ──retry──▶ proposed

`needs_acceptance` (decision D6): the candidate image fixed the targeted findings but
introduced new critical or high ones, so an operator must accept it before it is ready.
`completed` is only reached when a complete rescan of the real image no longer shows any
targeted finding. `published` means a GitHub pull request is open (decision D4); it fails if the
pull request is closed unmerged or the rebuilt image still has a targeted finding.
Events record history; this status column is the current state.
"""

from __future__ import annotations

from src.db.models import RemediationStatus as S

TRANSITIONS: dict[S, frozenset[S]] = {
    S.PROPOSED: frozenset({S.APPROVED, S.CANCELLED}),
    S.APPROVED: frozenset({S.BUILDING, S.CANCELLED}),
    S.BUILDING: frozenset({S.VERIFYING, S.FAILED, S.CANCELLED}),
    S.VERIFYING: frozenset({S.READY, S.NEEDS_ACCEPTANCE, S.FAILED, S.CANCELLED}),
    S.NEEDS_ACCEPTANCE: frozenset({S.READY, S.CANCELLED}),
    S.READY: frozenset({S.PUBLISHED, S.COMPLETED, S.CANCELLED}),
    S.PUBLISHED: frozenset({S.COMPLETED, S.FAILED, S.CANCELLED}),
    S.FAILED: frozenset({S.PROPOSED, S.CANCELLED}),
    S.COMPLETED: frozenset(),
    S.CANCELLED: frozenset(),
}

TERMINAL = frozenset({S.COMPLETED, S.FAILED, S.CANCELLED})
ACTIVE = frozenset({S.BUILDING, S.VERIFYING})

LABELS = {
    S.PROPOSED: "Awaiting approval",
    S.APPROVED: "Approved, not started",
    S.BUILDING: "Building patched image",
    S.VERIFYING: "Scanning patched image",
    S.NEEDS_ACCEPTANCE: "Needs acceptance: new findings",
    S.READY: "Verified, waiting for the image to be rebuilt",
    S.PUBLISHED: "Pull request open",
    S.COMPLETED: "Completed",
    S.FAILED: "Failed",
    S.CANCELLED: "Cancelled",
}


class InvalidRemediationTransition(ValueError):
    """Raised when a remediation attempts an illegal lifecycle transition."""


def transition(current: S, target: S) -> S:
    """Validate and return a legal target state."""
    if current == target:
        return target
    if target not in TRANSITIONS.get(current, frozenset()):
        raise InvalidRemediationTransition(f"Cannot transition remediation from {current.value} to {target.value}")
    return target
