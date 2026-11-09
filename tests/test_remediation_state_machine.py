"""Tests for remediation lifecycle enforcement."""

import pytest

from src.db.models import RemediationStatus
from src.remediation.state_machine import (
    InvalidRemediationTransition,
    transition,
)


@pytest.mark.parametrize(
    "current,target",
    [
        (RemediationStatus.PENDING, RemediationStatus.ANALYZING),
        (RemediationStatus.ANALYZING, RemediationStatus.PATCHING),
        (RemediationStatus.PATCHING, RemediationStatus.BUILDING),
        (RemediationStatus.BUILDING, RemediationStatus.VERIFYING),
        (RemediationStatus.VERIFYING, RemediationStatus.PR_OPENED),
        (RemediationStatus.PR_OPENED, RemediationStatus.COMPLETED),
        (RemediationStatus.REQUIRES_REVIEW, RemediationStatus.ANALYZING),
    ],
)
def test_valid_transitions_are_accepted(current, target):
    assert transition(current, target) == target


@pytest.mark.parametrize(
    "current,target",
    [
        (RemediationStatus.PENDING, RemediationStatus.COMPLETED),
        (RemediationStatus.ANALYZING, RemediationStatus.COMPLETED),
        (RemediationStatus.PR_OPENED, RemediationStatus.PATCHING),
        (RemediationStatus.COMPLETED, RemediationStatus.ANALYZING),
        (RemediationStatus.FAILED, RemediationStatus.PENDING),
    ],
)
def test_invalid_transitions_fail_closed(current, target):
    with pytest.raises(InvalidRemediationTransition):
        transition(current, target)


def test_same_state_is_idempotent():
    assert transition(RemediationStatus.PENDING, RemediationStatus.PENDING) == RemediationStatus.PENDING
