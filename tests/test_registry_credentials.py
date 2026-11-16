import json

import pytest

from src.scan.registry import credentials_for_host, registry_credentials_from_env, registry_env_keys


def test_registry_credential_requirements_are_explicit():
    assert registry_env_keys("dockerhub") == ("DOCKERHUB_USERNAME", "DOCKERHUB_PASSWORD")
    assert registry_env_keys("harbor.example") == ("REGISTRY_CREDENTIALS_JSON",)


def test_registry_credentials_normalize_supported_provider_env():
    credentials = registry_credentials_from_env(
        {
            "DOCKERHUB_USERNAME": "alice",
            "DOCKERHUB_PASSWORD": "secret",
            "GITHUB_TOKEN": "ghs-token",
        }
    )
    assert credentials["dockerhub"] == ("alice", "secret")
    assert credentials["ghcr.io"] == ("gh_token", "ghs-token")


@pytest.mark.parametrize(
    "env",
    [
        {"DOCKERHUB_USERNAME": "alice"},
        {"AWS_ACCESS_KEY_ID": "key"},
        {"REGISTRY_CREDENTIALS_JSON": "not json"},
        {"REGISTRY_CREDENTIALS_JSON": json.dumps({"harbor.example": {"username": "bot"}})},
    ],
)
def test_registry_credentials_reject_partial_or_malformed_configuration(env):
    with pytest.raises(ValueError):
        registry_credentials_from_env(env)


def test_credentials_are_chosen_by_registry_host():
    env = {
        "DOCKERHUB_USERNAME": "alice",
        "DOCKERHUB_PASSWORD": "pw",
        "GITHUB_TOKEN": "ghs",
        "GITLAB_TOKEN": "glt",
        "REGISTRY_CREDENTIALS_JSON": json.dumps({"harbor.example": {"username": "bot", "password": "s3"}}),
    }
    assert credentials_for_host("registry-1.docker.io", env) == ("alice", "pw")
    assert credentials_for_host("ghcr.io", env) == ("gh_token", "ghs")
    assert credentials_for_host("registry.gitlab.com", env) == ("gitlab-ci-token", "glt")
    assert credentials_for_host("harbor.example", env) == ("bot", "s3")
    assert credentials_for_host("registry:5000", env) is None
