import pytest

from src.scan.registry import registry_credentials_from_env, registry_env_keys


def test_registry_credential_requirements_are_explicit():
    assert registry_env_keys("ecr") == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    assert registry_env_keys("private.example") == ()


def test_registry_credentials_normalize_supported_provider_env():
    credentials = registry_credentials_from_env({
        "DOCKERHUB_USERNAME": "alice",
        "DOCKERHUB_PASSWORD": "secret",
        "GITHUB_TOKEN": "ghs-token",
        "AWS_ACCESS_KEY_ID": "key",
        "AWS_SECRET_ACCESS_KEY": "secret",
    })
    assert credentials["dockerhub"] == ("alice", "secret")
    assert credentials["ghcr.io"] == ("gh_token", "ghs-token")
    assert credentials["ecr"] == ("key", "secret")


def test_registry_credentials_reject_partial_pairs():
    with pytest.raises(ValueError, match="DOCKERHUB"):
        registry_credentials_from_env({"DOCKERHUB_USERNAME": "alice"})
    with pytest.raises(ValueError, match="AWS"):
        registry_credentials_from_env({"AWS_ACCESS_KEY_ID": "key"})
