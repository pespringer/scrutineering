"""Deterministic security-policy evaluation for persisted scan results."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from src.db.models import PolicyType, SecurityPolicy, ScanFinding


SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _value(value) -> str:
    return getattr(value, "value", value)


def evaluate_policy(policy: SecurityPolicy, findings: Iterable[ScanFinding], image_name: str) -> dict[str, object]:
    """Evaluate one policy without mutating state."""
    findings = list(findings)
    policy_type = _value(policy.policy_type)
    rules = policy.rules or {}
    detail: dict[str, object] = {"policy_type": policy_type, "image_name": image_name}
    violated = False

    if policy_type == PolicyType.SEVERITY_THRESHOLD.value:
        counts = Counter(_value(finding.severity) or "unknown" for finding in findings)
        limits = {severity: int(rules[f"max_{severity}"]) for severity in SEVERITIES if f"max_{severity}" in rules}
        exceeded = {severity: {"observed": counts.get(severity, 0), "maximum": limit} for severity, limit in limits.items() if counts.get(severity, 0) > limit}
        detail.update({"counts": dict(counts), "limits": limits, "exceeded": exceeded})
        violated = bool(exceeded)
    elif policy_type in {PolicyType.IMAGE_ALLOWLIST.value, PolicyType.IMAGE_DENYLIST.value}:
        images = rules.get("images", policy.image_filters.get("images", []) if policy.image_filters else [])
        configured = {str(image).strip() for image in images if str(image).strip()}
        matched = image_name in configured
        violated = not matched if policy_type == PolicyType.IMAGE_ALLOWLIST.value else matched
        detail.update({"configured_images": sorted(configured), "matched": matched})
    else:
        detail["unsupported"] = True

    return {"policy_id": policy.id, "name": policy.name, "violated": violated, "action": _value(policy.action) if violated else None, "detail": detail}
