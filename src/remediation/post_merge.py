"""Fail-closed post-merge verification decision."""

from __future__ import annotations
import re


def evaluate_post_merge(*, expected_digest: str, observed_digest: str | None, required_scan_status: str, findings_before: int, findings_after: int) -> dict[str, object]:
    reasons: list[str] = []
    if findings_before < 0 or findings_after < 0:
        reasons.append("finding_counts_invalid")
    digest_valid = not expected_digest.startswith("sha256:") or bool(re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest))
    if not digest_valid or observed_digest != expected_digest:
        reasons.append("deployed digest does not match the verified artifact")
    if required_scan_status != "completed":
        reasons.append("post-merge scan did not complete")
    if findings_after > findings_before:
        reasons.append("post-merge findings increased")
    return {"status": "verified" if not reasons else "rollback_required", "reasons": reasons, "findings_delta": findings_after - findings_before}
