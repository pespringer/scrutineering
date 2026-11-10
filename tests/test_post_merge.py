from src.remediation.post_merge import evaluate_post_merge


def test_post_merge_requires_matching_digest_and_non_regression():
    digest = "sha256:" + "a" * 64
    assert evaluate_post_merge(expected_digest=digest, observed_digest=digest, required_scan_status="completed", findings_before=4, findings_after=2)["status"] == "verified"
    assert evaluate_post_merge(expected_digest=digest, observed_digest="sha256:" + "b" * 64, required_scan_status="completed", findings_before=1, findings_after=2)["status"] == "rollback_required"
