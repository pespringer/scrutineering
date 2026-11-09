import pytest

from src.db.models import RemediationStatus
from src.remediation.lifecycle import RemediationLifecycle
from src.remediation.state_machine import InvalidRemediationTransition


def test_lifecycle_tracks_execution_stages():
    lifecycle = RemediationLifecycle()
    for status in (RemediationStatus.ANALYZING, RemediationStatus.PATCHING, RemediationStatus.BUILDING, RemediationStatus.VERIFYING, RemediationStatus.PR_OPENED, RemediationStatus.COMPLETED):
        lifecycle.advance(status)
    assert lifecycle.terminal
    assert lifecycle.history[-1] == RemediationStatus.COMPLETED


def test_lifecycle_rejects_skipping_required_stages():
    lifecycle = RemediationLifecycle()
    with pytest.raises(InvalidRemediationTransition):
        lifecycle.advance(RemediationStatus.COMPLETED)
    lifecycle.fail()
    with pytest.raises(InvalidRemediationTransition):
        lifecycle.advance(RemediationStatus.ANALYZING)
