import pytest

from src.remediation.publication import build_publication_plan


def test_publication_plan_requires_allowlist_evidence_and_protected_base():
    plan = build_publication_plan(
        provider="github", repository="acme/api", head="auto/fix-1", base="main",
        idempotency_key="run-1", commit="a" * 40, evidence_verified=True,
        allowed_repositories={"acme/api"},
    )
    assert plan.rollback_command == ("git", "revert", "--no-edit", "a" * 40)


@pytest.mark.parametrize("kwargs", [
    {"repository": "other/api"},
    {"base": "develop"},
    {"evidence_verified": False},
    {"head": "../bad"},
])
def test_publication_plan_fails_closed(kwargs):
    values = {"provider": "github", "repository": "acme/api", "head": "auto/fix", "base": "main", "idempotency_key": "run", "commit": "a" * 40, "evidence_verified": True, "allowed_repositories": {"acme/api"}}
    values.update(kwargs)
    with pytest.raises(ValueError):
        build_publication_plan(**values)
