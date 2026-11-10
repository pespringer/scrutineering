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


def test_lifecycle_recovers_from_ordered_durable_events():
    emitted = []
    lifecycle = RemediationLifecycle(remediation_id=7, event_sink=emitted.append)
    lifecycle.advance(RemediationStatus.ANALYZING)
    lifecycle.advance(RemediationStatus.PATCHING)
    recovered = RemediationLifecycle.recover(emitted, remediation_id=7)
    assert recovered.status == RemediationStatus.PATCHING
    assert recovered.history == [RemediationStatus.PENDING, RemediationStatus.ANALYZING, RemediationStatus.PATCHING]


def test_lifecycle_recovery_rejects_event_sequence_gaps():
    with pytest.raises(ValueError, match="gap"):
        RemediationLifecycle.recover([{"sequence": 2, "event_type": "analyzing"}])
