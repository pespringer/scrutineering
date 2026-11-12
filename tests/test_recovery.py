import pytest

from src.remediation.recovery import transition_recovery_status


def test_recovery_lifecycle_allows_acknowledge_then_complete():
    assert transition_recovery_status("requested", "acknowledged") == "acknowledged"
    assert transition_recovery_status("acknowledged", "completed") == "completed"


def test_recovery_lifecycle_rejects_reopening_terminal_state():
    with pytest.raises(ValueError):
        transition_recovery_status("completed", "requested")
