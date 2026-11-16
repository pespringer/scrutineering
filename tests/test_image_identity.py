"""Tests for canonical container image identity handling."""

import pytest

from src.db.models import ImageRegistry
from src.scan.image_identity import parse_image_reference


def test_digest_reference_is_immutable_and_canonical():
    identity = parse_image_reference("ghcr.io/acme/api@sha256:" + "a" * 64)

    assert identity.registry == ImageRegistry.GHCR
    assert identity.repo_name == "ghcr.io/acme/api"
    assert identity.is_immutable is True
    assert identity.reference == "ghcr.io/acme/api@sha256:" + "a" * 64
    assert identity.identity_key.endswith("@sha256:" + "a" * 64)


def test_tag_reference_is_explicitly_mutable():
    identity = parse_image_reference("nginx:1.25")

    assert identity.is_immutable is False
    assert identity.reference == "nginx:1.25"


@pytest.mark.parametrize("value", ["", "nginx@sha256:short", "nginx@md5:" + "a" * 64])
def test_invalid_references_are_rejected(value):
    with pytest.raises(ValueError):
        parse_image_reference(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("nginx", "nginx:latest"),
        ("library/nginx:1.27", "nginx:1.27"),
        ("docker.io/library/nginx:1.27", "nginx:1.27"),
        ("index.docker.io/acme/api:v1", "acme/api:v1"),
        ("registry:5000/scrutineering-test:latest", "registry:5000/scrutineering-test:latest"),
        ("localhost/app:dev", "localhost/app:dev"),
        ("us.gcr.io/proj/app:v2", "us.gcr.io/proj/app:v2"),
        ("ghcr.io/acme/api:v1", "ghcr.io/acme/api:v1"),
    ],
)
def test_reference_round_trips_without_losing_the_host(value, expected):
    assert parse_image_reference(value).reference == expected
    assert parse_image_reference(expected).reference == expected


@pytest.mark.parametrize(
    ("value", "registry"),
    [
        ("nginx", ImageRegistry.DOCKER_HUB),
        ("ghcr.io/a/b", ImageRegistry.GHCR),
        ("europe-docker.pkg.dev/p/r/app", ImageRegistry.GCR),
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com/app", ImageRegistry.ECR),
        ("registry.gitlab.com/group/app", ImageRegistry.GITLAB),
        ("quay.io/org/app", ImageRegistry.QUAY),
        ("registry:5000/app", ImageRegistry.OTHER),
    ],
)
def test_registry_is_classified_from_the_host(value, registry):
    assert parse_image_reference(value).registry == registry


def test_registry_api_coordinates():
    hub = parse_image_reference("alpine:3.20")
    assert (hub.host, hub.repository) == ("registry-1.docker.io", "library/alpine")
    local = parse_image_reference("registry:5000/team/app:1")
    assert (local.host, local.repository) == ("registry:5000", "team/app")
