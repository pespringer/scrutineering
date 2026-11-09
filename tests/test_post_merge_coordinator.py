from src.remediation.post_merge_coordinator import PostMergeCoordinator


def test_coordinator_triggers_rollback_on_regression():
    calls = []
    result = PostMergeCoordinator(rollback=lambda result: calls.append(result)).verify(expected_digest="a", observed_digest="b", required_scan_status="completed", findings_before=1, findings_after=2)
    assert result["status"] == "rollback_required"
    assert len(calls) == 1
