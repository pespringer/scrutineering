from src.remediation.post_merge import evaluate_post_merge


def test_post_merge_requires_matching_digest_and_non_regression():
    assert evaluate_post_merge(expected_digest="sha256:x", observed_digest="sha256:x", required_scan_status="completed", findings_before=4, findings_after=2)["status"] == "verified"
    assert evaluate_post_merge(expected_digest="sha256:x", observed_digest="sha256:y", required_scan_status="completed", findings_before=1, findings_after=2)["status"] == "rollback_required"
