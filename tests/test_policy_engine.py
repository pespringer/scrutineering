from types import SimpleNamespace

from src.db.models import PolicyAction, PolicyType, Severity
from src.risk.policy_engine import evaluate_policy


def test_severity_policy_reports_exceeded_thresholds():
    policy = SimpleNamespace(id=4, name="release gate", policy_type=PolicyType.SEVERITY_THRESHOLD, action=PolicyAction.BLOCK, rules={"max_critical": 0, "max_high": 1}, image_filters={})
    findings = [SimpleNamespace(severity=Severity.CRITICAL), SimpleNamespace(severity=Severity.HIGH), SimpleNamespace(severity=Severity.HIGH)]

    result = evaluate_policy(policy, findings, "alpine:3.20")

    assert result["violated"] is True
    assert result["action"] == "block"
    assert result["detail"]["exceeded"] == {"critical": {"observed": 1, "maximum": 0}, "high": {"observed": 2, "maximum": 1}}


def test_image_denylist_matches_exact_image_reference():
    policy = SimpleNamespace(id=5, name="deny fixture", policy_type=PolicyType.IMAGE_DENYLIST, action=PolicyAction.ALERT, rules={"images": ["alpine:3.20"]}, image_filters={})
    result = evaluate_policy(policy, [], "alpine:3.20")
    assert result["violated"] is True
    assert result["detail"]["matched"] is True
