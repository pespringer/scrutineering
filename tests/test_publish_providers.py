"""Publishing goes through one provider interface (docs/design/gitlab-publishing.md, step 1)."""

from __future__ import annotations

import pytest

from src.remediation import publish
from src.remediation.sources import PublicationTarget, publication_target, source_token


def test_a_github_source_publishes_to_github():
    assert publication_target("https://github.com/acme/app.git") == PublicationTarget("github", "acme/app")
    assert publication_target("https://github.com/acme/app/") == PublicationTarget("github", "acme/app")


@pytest.mark.parametrize(
    "url",
    [None, "", "app", "https://github.example.com/acme/app", "https://gitlab.com/acme/app", "http://github.com/a/b"],
)
def test_other_sources_have_no_publication_target(url):
    assert publication_target(url) is None


def test_only_sources_on_a_provider_are_cloned_with_its_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    assert source_token("https://github.com/acme/app") == "gh-token"
    assert source_token("https://git.example.com/acme/app") == ""
    assert source_token("local/app") == ""


def test_the_github_client_satisfies_the_provider_interface(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    provider = publish.provider_for(PublicationTarget("github", "acme/app"))
    assert isinstance(provider, publish.GitHub)
    assert (provider.name, provider.label, provider.token()) == ("github", "GitHub", "gh-token")
    assert provider.clone_url("acme/app") == "https://github.com/acme/app.git"
    for method in ("default_branch", "open_change"):
        assert callable(getattr(provider, method))


def test_open_change_returns_the_pull_requests_number_and_url():
    class Client(publish.GitHub):
        def open_pull_request(self, repository, **kwargs):
            return {"number": 12, "html_url": f"https://github.com/{repository}/pull/12"}

    change = Client("t").open_change("acme/app", head="h", base="main", title="t", body="b")
    assert change == publish.Change(number=12, url="https://github.com/acme/app/pull/12")


def test_an_unsupported_provider_is_a_publish_error():
    with pytest.raises(publish.PublishError, match="not supported"):
        publish.provider_for(PublicationTarget("bitbucket", "acme/app"))
