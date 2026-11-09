from src.remediation.approval import issue_approval
from src.remediation.executor import execute_remediation


def test_executor_requires_valid_approval_when_configured(tmp_path):
    token = issue_approval("rem-1", "alice", "secret")
    result = execute_remediation(tmp_path, [], lambda *_: None, [], evidence_verified=True, approval_token=token, approval_secret="secret", remediation_id="rem-1")
    assert result.status != "blocked"
