from src.remediation.worker import execution_enabled


def test_remediation_execution_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("REMEDIATION_EXECUTION_ENABLED", raising=False)
    assert execution_enabled() is False


def test_remediation_execution_requires_explicit_enablement(monkeypatch):
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    assert execution_enabled() is True
