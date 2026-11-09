"""Tests for canonical container image identity handling."""

import pytest

from src.db.models import ImageRegistry
from src.scan.image_identity import parse_image_reference


def test_digest_reference_is_immutable_and_canonical():
    identity = parse_image_reference(
        "ghcr.io/acme/api@sha256:" + "a" * 64
    )

    assert identity.registry == ImageRegistry.GHCR
    assert identity.repo_name == "acme/api"
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
