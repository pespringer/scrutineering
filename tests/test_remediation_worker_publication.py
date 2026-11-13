from types import SimpleNamespace

import pytest

import src.remediation.worker as worker


class _Query:
    def filter_by(self, **_kwargs):
        return self

    def first(self):
        return None


class _Session:
    def __init__(self):
        self.added = []

    def query(self, _model):
        return _Query()

    def add(self, value):
        self.added.append(value)

    def flush(self):
        self.added[-1].id = 17


def test_worker_publication_persists_provider_result(monkeypatch):
    session = _Session()
    remediation = SimpleNamespace(id=4, pr_url=None, pr_number=None, status=None)
    monkeypatch.setenv("REMEDIATION_PUBLICATION_PROVIDER", "github")
    monkeypatch.setenv("REMEDIATION_PUBLICATION_REPOSITORY", "acme/service")
    monkeypatch.setenv("REMEDIATION_PUBLICATION_BASE", "main")
    monkeypatch.setenv("REMEDIATION_ALLOWED_REPOSITORIES", "acme/service")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(worker, "build_publication_plan", lambda **kwargs: SimpleNamespace(**kwargs, rollback_command=()))
    monkeypatch.setattr(worker, "publish_validated_plan", lambda **kwargs: SimpleNamespace(provider="github", repository="acme/service", number=12, url="https://github.com/acme/service/pull/12"))

    result = worker._publish_branch(session, remediation, "scrutineering/remediation/4", "a" * 40)

    assert result["number"] == 12
    assert remediation.pr_number == 12
    assert remediation.pr_url.endswith("/12")
    assert remediation.status.value == "pr_opened"
    assert session.added[0].status == "published"


def test_worker_publication_requires_allowlisted_repository(monkeypatch):
    monkeypatch.setenv("REMEDIATION_PUBLICATION_REPOSITORY", "acme/service")
    monkeypatch.setenv("REMEDIATION_ALLOWED_REPOSITORIES", "")
    with pytest.raises(ValueError, match="allowlisted"):
        worker._publish_branch(_Session(), SimpleNamespace(id=4), "scrutineering/remediation/4", "a" * 40)
