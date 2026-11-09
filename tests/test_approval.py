import pytest

from src.remediation.approval import issue_approval, verify_approval


def test_approval_token_is_scoped_and_expiring():
    token = issue_approval("rem-1", "alice", "secret", ttl_seconds=60, now=100)
    assert verify_approval(token, "rem-1", "secret", now=159)["approver"] == "alice"
    with pytest.raises(ValueError):
        verify_approval(token, "rem-2", "secret", now=100)
    with pytest.raises(ValueError):
        verify_approval(token, "rem-1", "secret", now=161)
