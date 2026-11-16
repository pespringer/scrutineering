"""Tag-to-digest resolution through the registry API, including auth challenges."""

import base64
import io
import json
from email.message import Message
from urllib.error import HTTPError

import pytest

from src.scan.image_identity import parse_image_reference
from src.scan.registry import resolve_digest

DIGEST = "sha256:" + "d" * 64


class Response:
    def __init__(self, headers=None, body=b""):
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _unauthorized(url, challenge):
    headers = Message()
    headers["WWW-Authenticate"] = challenge
    return HTTPError(url, 401, "Unauthorized", headers, io.BytesIO())


def test_public_docker_hub_image_resolves_through_an_anonymous_bearer_token():
    requests = []

    def opener(request, timeout):
        requests.append(request)
        if request.full_url.startswith("https://auth.docker.io/token"):
            return Response(body=json.dumps({"token": "anon"}).encode())
        if "Authorization" not in request.headers:
            raise _unauthorized(
                request.full_url,
                'Bearer realm="https://auth.docker.io/token",'
                'service="registry.docker.io",scope="repository:library/alpine:pull"',
            )
        return Response({"Docker-Content-Digest": DIGEST})

    assert resolve_digest(parse_image_reference("alpine:3.20"), opener=opener) == DIGEST
    manifest, token, retry = requests
    assert manifest.full_url == "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"
    assert manifest.get_method() == "HEAD"
    assert "scope=repository%3Alibrary%2Falpine%3Apull" in token.full_url
    assert "Authorization" not in token.headers
    assert retry.headers["Authorization"] == "Bearer anon"


def test_credentials_are_sent_to_the_token_endpoint():
    seen = {}

    def opener(request, timeout):
        if request.full_url.startswith("https://ghcr.io/token"):
            seen["token_auth"] = request.headers.get("Authorization")
            return Response(body=json.dumps({"access_token": "t"}).encode())
        if "Authorization" not in request.headers:
            raise _unauthorized(request.full_url, 'Bearer realm="https://ghcr.io/token",service="ghcr.io"')
        return Response({"Docker-Content-Digest": DIGEST})

    resolve_digest(parse_image_reference("ghcr.io/acme/api:v1"), credentials=("bot", "pw"), opener=opener)
    assert seen["token_auth"] == "Basic " + base64.b64encode(b"bot:pw").decode()


def test_local_registry_over_http_needs_no_auth():
    def opener(request, timeout):
        assert request.full_url == "http://registry:5000/v2/team/app/manifests/1.0"
        return Response({"Docker-Content-Digest": DIGEST})

    assert resolve_digest(parse_image_reference("registry:5000/team/app:1.0"), scheme="http", opener=opener) == DIGEST


def test_basic_challenge_without_credentials_is_refused():
    def opener(request, timeout):
        raise _unauthorized(request.full_url, 'Basic realm="harbor"')

    with pytest.raises(PermissionError):
        resolve_digest(parse_image_reference("harbor.example/team/app:1"), opener=opener)


def test_missing_digest_header_is_an_error():
    with pytest.raises(RuntimeError, match="sha256 digest"):
        resolve_digest(
            parse_image_reference("registry:5000/a:1"), scheme="http", opener=lambda request, timeout: Response()
        )


def test_pinned_reference_is_returned_without_a_request():
    pinned = parse_image_reference(f"nginx@{DIGEST}")
    assert resolve_digest(pinned, opener=lambda *a, **k: pytest.fail("no request expected")) == DIGEST
