import pytest

from src.remediation.rollback import build_rollback_plan


def test_rollback_plan_is_explicit_and_requires_verification():
    plan = build_rollback_plan("a" * 40)
    assert plan.command == ("git", "revert", "--no-edit", "a" * 40)
    assert plan.verification_required


def test_rollback_plan_rejects_injected_commands():
    with pytest.raises(ValueError):
        build_rollback_plan("abc; git push")
