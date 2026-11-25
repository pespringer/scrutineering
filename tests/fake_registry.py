"""A fake of the distribution API, at the level of the registry client's opener."""

from __future__ import annotations

import hashlib
import io
import json
from email.message import Message
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit

HOST = "registry:5000"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"


def digest_of(body: bytes) -> str:
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, headers: dict[str, str]):
        super().__init__(body)
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value


class FakeRegistry:
    """The distribution API, as `registry:2` answers it: an index is 404 unless the client accepts it."""

    def __init__(self, page_size: int = 1000):
        self.tags: dict[str, dict[str, str]] = {}
        self.content: dict[str, tuple[str, bytes]] = {}
        self.requests: list[tuple[str, str]] = []
        self.page_size = page_size
        self.failing: set[str] = set()
        # What DELETE answers: None deletes (registry:3), 400 is registry:2, 405 is deletion turned off.
        self.delete_status: int | None = None

    def put(self, document: dict, media_type: str = "application/json") -> str:
        body = json.dumps(document).encode()
        self.content[digest_of(body)] = (media_type, body)
        return digest_of(body)

    def image(self, layers: dict[str, int], *, arch: str = "amd64", config: dict | None = None, **extra) -> str:
        config_digest = self.put({"os": "linux", "architecture": arch, "config": config or {}, **extra})
        manifest = {
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": {"digest": config_digest, "size": len(self.content[config_digest][1])},
            "layers": [{"digest": digest_of(name.encode()), "size": size} for name, size in layers.items()],
        }
        return self.put(manifest, MANIFEST)

    def index(self, *children: tuple[str, str]) -> str:
        manifests = []
        for digest, platform in children:
            os_name, _, arch = platform.partition("/")
            manifests.append({"digest": digest, "platform": {"os": os_name, "architecture": arch}})
        return self.put({"schemaVersion": 2, "mediaType": INDEX, "manifests": manifests}, INDEX)

    def tag(self, repository: str, tag: str, digest: str) -> None:
        self.tags.setdefault(repository, {})[tag] = digest

    def _page(self, path: str, query: dict, key: str, values: list[str]) -> FakeResponse:
        start = int(query.get("last", ["0"])[0])
        page, end = values[start : start + self.page_size], start + self.page_size
        headers = {"Link": f'<http://elsewhere.example{path}?last={end}>; rel="next"'} if end < len(values) else {}
        return FakeResponse(json.dumps({key: page or None}).encode(), headers)

    def __call__(self, request, timeout):
        url = urlsplit(request.full_url)
        assert url.netloc == HOST, f"left the registry: {request.full_url}"
        path, query = unquote(url.path), parse_qs(url.query)
        self.requests.append((request.get_method(), path))
        if path in self.failing:
            raise HTTPError(request.full_url, 500, "broken", Message(), None)
        if path == "/v2/_catalog":
            return self._page(path, query, "repositories", list(self.tags))
        repository, kind, reference = path.removeprefix("/v2/").rsplit("/", 2)
        if kind == "tags":
            return self._page(path, query, "tags", list(self.tags[repository]))
        if request.get_method() == "DELETE":
            assert kind == "manifests" and not reference.startswith("sha256:"), "only ever delete by tag"
            status = self.delete_status or (None if reference in self.tags.get(repository, {}) else 404)
            if status:
                raise HTTPError(request.full_url, status, "refused", Message(), None)
            del self.tags[repository][reference]
            return FakeResponse(b"", {})
        digest = self.tags.get(repository, {}).get(reference, reference)
        media_type, body = self.content.get(digest, ("", b""))
        if not body or (kind == "manifests" and media_type not in request.get_header("Accept")):
            raise HTTPError(request.full_url, 404, "not found", Message(), None)
        headers = {"Docker-Content-Digest": digest, "Content-Length": str(len(body))}
        return FakeResponse(b"" if request.get_method() == "HEAD" else body, headers)
