"""Fail-closed post-merge verification decision."""

from __future__ import annotations


def evaluate_post_merge(*, expected_digest: str, observed_digest: str | None, required_scan_status: str, findings_before: int, findings_after: int) -> dict[str, object]:
    reasons: list[str] = []
    if not expected_digest or observed_digest != expected_digest:
        reasons.append("deployed digest does not match the verified artifact")
    if required_scan_status != "completed":
        reasons.append("post-merge scan did not complete")
    if findings_after > findings_before:
        reasons.append("post-merge findings increased")
    return {"status": "verified" if not reasons else "rollback_required", "reasons": reasons, "findings_delta": findings_after - findings_before}
