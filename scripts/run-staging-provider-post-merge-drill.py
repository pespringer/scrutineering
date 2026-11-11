"""Deterministic provider publication -> merge -> verification drill."""

from src.remediation.post_merge import evaluate_post_merge
from src.remediation.provider_callbacks import normalize_callback
from src.remediation.rollback import build_rollback_plan

DIGEST = "sha256:" + "a" * 64


def main() -> None:
    healthy = normalize_callback(
        provider="github", event_id="staging-healthy", event_type="pull_request",
        payload={"repository": {"full_name": "scrutineering/staging-app"}, "number": 41,
                 "pull_request": {"merged": True, "merge_commit_sha": "a" * 40},
                 "expected_digest": DIGEST, "observed_digest": DIGEST,
                 "scan_status": "completed", "findings_before": 4, "findings_after": 2},
    )
    result = evaluate_post_merge(expected_digest=healthy.expected_digest, observed_digest=healthy.observed_digest,
                                 required_scan_status=healthy.scan_status, findings_before=healthy.findings_before,
                                 findings_after=healthy.findings_after)
    assert result["status"] == "verified"
    print("PASS staging merge callback: verified")

    regression = normalize_callback(
        provider="gitlab", event_id="staging-regression", event_type="merge_request",
        payload={"repository": "scrutineering/staging-app", "number": 42, "merged": True,
                 "merge_commit": "b" * 40, "expected_digest": DIGEST,
                 "observed_digest": "sha256:" + "b" * 64, "scan_status": "completed",
                 "findings_before": 2, "findings_after": 5},
    )
    result = evaluate_post_merge(expected_digest=regression.expected_digest, observed_digest=regression.observed_digest,
                                 required_scan_status=regression.scan_status, findings_before=regression.findings_before,
                                 findings_after=regression.findings_after)
    assert result["status"] == "rollback_required"
    rollback = build_rollback_plan(regression.merge_commit or "")
    assert rollback.command == ("git", "revert", "--no-edit", regression.merge_commit)
    print("PASS staging regression callback: rollback_required")


if __name__ == "__main__":
    main()
