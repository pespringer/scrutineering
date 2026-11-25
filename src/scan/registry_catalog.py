"""Reading the bundled registry: its tags, what each image holds, and how much it stores.

See docs/design/registry-management.md. This only talks to the configured local registry, never
follows a redirect away from it, and checks names before they go into a URL. Manifests and configs
are written by whoever built the image: they are size-limited, checked against their digest, and
parsed defensively. A manifest never changes for a digest, so what's parsed from it is cached.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.client import HTTPException
from typing import Any, Callable, Iterable
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from src.config import get_settings

logger = logging.getLogger(__name__)

INDEX_TYPES = frozenset(
    {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
)
MANIFEST_TYPES = frozenset(
    {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
)
ACCEPT = ", ".join(sorted(INDEX_TYPES | MANIFEST_TYPES))
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20
MAX_PLATFORMS = 64
TIMEOUT_SECONDS = 10
CACHE_PREFIX = "scrutineering:registry-image:v1:"
CACHE_TTL_SECONDS = 7 * 24 * 3600

_COMPONENT = r"[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*"
_REPOSITORY = re.compile(rf"{_COMPONENT}(?:/{_COMPONENT})*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="?next"?')
_SETTING = re.compile(r"^(?:.*?#\(nop\)\s+)?(ENV|ARG)\b\s*([A-Za-z_]\w*)?", re.IGNORECASE | re.DOTALL)
_BUILD_ARGS = re.compile(r"^(RUN\s+)?\|\d+\s", re.IGNORECASE)
_SHELL = " /bin/sh -c "


class RegistryError(Exception):
    """The registry's answer can't be used. The message is shown to the operator."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def valid_repository(name: str) -> bool:
    return len(name) <= 255 and bool(_REPOSITORY.fullmatch(name))


def valid_tag(tag: str) -> bool:
    return bool(_TAG.fullmatch(tag))


def registry_url(configured: str, host: str) -> str:
    """An explicit URL, or the host over HTTP when REGISTRY_INSECURE is set (HTTPS otherwise)."""
    if configured.strip():
        return configured.strip().rstrip("/")
    return f"{'http' if get_settings().registry_insecure else 'https'}://{host.strip()}"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_open = build_opener(_NoRedirect).open


class RegistryClient:
    """The distribution API of one registry, without authentication."""

    def __init__(self, base_url: str, opener: Callable | None = None):
        self.base_url = base_url
        self._opener = opener or _open

    @classmethod
    def local(cls) -> "RegistryClient":
        settings = get_settings()
        return cls(registry_url(settings.local_registry_url, settings.local_registry_host))

    def _request(self, path: str, *, accept: str = "application/json", method: str = "GET") -> tuple[Any, bytes]:
        request = Request(f"{self.base_url}{path}", headers={"Accept": accept}, method=method)
        try:
            with self._opener(request, timeout=TIMEOUT_SECONDS) as response:
                body = b"" if method == "HEAD" else response.read(MAX_DOCUMENT_BYTES + 1)
                headers = response.headers
        except HTTPError as error:
            raise RegistryError(f"the registry answered {error.code}", error.code) from error
        except (OSError, HTTPException) as error:
            raise RegistryError("the registry can't be reached") from error
        if len(body) > MAX_DOCUMENT_BYTES:
            raise RegistryError(f"the document is over {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB")
        return headers, body

    def _pages(self, path: str, key: str) -> list[str]:
        """A paginated listing. Only the path and query of a `Link` are used, never its host."""
        values: list[str] = []
        for _ in range(MAX_PAGES):
            headers, body = self._request(path)
            page = _document(body).get(key)
            values.extend(value for value in page or [] if isinstance(value, str))
            match = _NEXT_LINK.search(headers.get("Link") or "")
            if not match:
                return values
            link = urlsplit(match.group(1))
            if not link.path.startswith("/v2/"):
                return values
            path = f"{link.path}?{link.query}"
        logger.warning("stopped listing %s after %d pages", key, MAX_PAGES)
        return values

    def repositories(self) -> list[str]:
        return [name for name in self._pages("/v2/_catalog?n=1000", "repositories") if valid_repository(name)]

    def tags(self, repository: str) -> list[str]:
        path = f"/v2/{quote(repository, safe='/')}/tags/list?n=1000"
        try:
            return sorted({tag for tag in self._pages(path, "tags") if valid_tag(tag)})
        except RegistryError as error:
            if error.status == 404:  # its last tag went between the two listings
                return []
            raise

    def digest(self, repository: str, tag: str) -> str:
        path = f"/v2/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}"
        headers, _ = self._request(path, accept=ACCEPT, method="HEAD")
        digest = headers.get("Docker-Content-Digest") or ""
        if not _DIGEST.fullmatch(digest):
            raise RegistryError("the registry returned no digest")
        return digest

    def _content(self, kind: str, repository: str, digest: str, accept: str) -> bytes:
        if not _DIGEST.fullmatch(digest):
            raise RegistryError("the image has an unsupported digest")
        _, body = self._request(f"/v2/{quote(repository, safe='/')}/{kind}/{digest}", accept=accept)
        if f"sha256:{hashlib.sha256(body).hexdigest()}" != digest:
            raise RegistryError("the content doesn't match its digest")
        return body

    def manifest(self, repository: str, digest: str) -> tuple[dict, int]:
        body = self._content("manifests", repository, digest, ACCEPT)
        return _document(body), len(body)

    def config(self, repository: str, digest: str) -> dict:
        return _document(self._content("blobs", repository, digest, "*/*"))


def _document(body: bytes) -> dict:
    try:
        value = json.loads(body)
    except (ValueError, RecursionError) as error:
        raise RegistryError("the document isn't valid JSON") from error
    if not isinstance(value, dict):
        raise RegistryError("the document isn't a JSON object")
    return value


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _size(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _is_index(manifest: dict) -> bool:
    return manifest.get("mediaType") in INDEX_TYPES or ("manifests" in manifest and "layers" not in manifest)


def _platform(value: dict) -> str:
    parts = [_text(value.get(key)) for key in ("os", "architecture", "variant")]
    return "/".join(part for part in parts if part) or "unknown"


def _stored(descriptor: dict) -> bool:
    """Foreign (Windows base) layers are pulled from elsewhere; the registry doesn't hold them."""
    media_type = _text(descriptor.get("mediaType")) or ""
    return "foreign" not in media_type and "nondistributable" not in media_type


def _blobs(descriptors: Iterable[dict]) -> dict[str, int]:
    return {
        digest: _size(item.get("size"))
        for item in descriptors
        if _stored(item) and (digest := _text(item.get("digest"))) and _DIGEST.fullmatch(digest)
    }


@dataclass
class ImageSummary:
    """What one digest holds: its compressed size, its platforms, and every blob it keeps stored."""

    size: int = 0
    platforms: list[dict] = field(default_factory=list)
    attestations: int = 0
    blobs: dict[str, int] = field(default_factory=dict)

    def payload(self) -> dict:
        return {"size": self.size, "platforms": self.platforms, "attestations": self.attestations}


@dataclass
class _Child:
    """One platform's manifest, as its index (or the tag itself) names it."""

    digest: str
    platform: str | None
    attestation: bool = False


def _children(digest: str, manifest: dict) -> list[_Child]:
    if not _is_index(manifest):
        return [_Child(digest, None)]
    entries = _dicts(manifest.get("manifests"))
    if len(entries) > MAX_PLATFORMS:
        raise RegistryError(f"the index lists over {MAX_PLATFORMS} images")
    children = []
    for entry in entries:
        platform = _platform(_dict(entry.get("platform")))
        children.append(_Child(_text(entry.get("digest")) or "", platform, platform == "unknown/unknown"))
    return children


def summarize(client: RegistryClient, repository: str, digest: str) -> ImageSummary:
    """Read one image: its manifest, each platform's manifest, and the config that names a lone platform."""
    top, top_size = client.manifest(repository, digest)
    summary = ImageSummary(blobs={digest: top_size})
    layers: dict[str, int] = {}
    for child in _children(digest, top):
        manifest, size = (top, top_size) if child.digest == digest else client.manifest(repository, child.digest)
        summary.blobs[child.digest] = size
        config = _dict(manifest.get("config"))
        own_layers = _blobs(_dicts(manifest.get("layers")))
        summary.blobs.update(_blobs([config]) | own_layers)
        if child.attestation:
            summary.attestations += 1
            continue
        platform = child.platform or _platform(client.config(repository, _text(config.get("digest")) or ""))
        summary.platforms.append({"platform": platform, "size": sum(own_layers.values())})
        layers.update(own_layers)
    summary.size = sum(layers.values())
    return summary


def _redis():
    import redis

    return redis.Redis.from_url(get_settings().redis_url, socket_timeout=2, socket_connect_timeout=2)


def _cached(digests: list[str]) -> dict[str, ImageSummary]:
    found = {}
    try:
        values = _redis().mget([CACHE_PREFIX + digest for digest in digests]) if digests else []
        for digest, value in zip(digests, values):
            if value:
                found[digest] = ImageSummary(**json.loads(value))
    except Exception as error:  # noqa: BLE001 - the cache only saves requests
        logger.warning("could not read the registry cache: %s", error)
    return found


def _cache(summaries: dict[str, ImageSummary]) -> None:
    if not summaries:
        return
    try:
        pipeline = _redis().pipeline()
        for digest, summary in summaries.items():
            value = {**summary.payload(), "blobs": summary.blobs}
            pipeline.set(CACHE_PREFIX + digest, json.dumps(value), ex=CACHE_TTL_SECONDS)
        pipeline.execute()
    except Exception as error:  # noqa: BLE001 - the cache only saves requests
        logger.warning("could not write the registry cache: %s", error)


@dataclass
class CatalogTag:
    repository: str
    tag: str
    digest: str | None = None
    summary: ImageSummary | None = None
    error: str | None = None


def _attempt(read: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return read(), None
    except RegistryError as error:
        return None, str(error)


def catalog(client: RegistryClient) -> list[CatalogTag]:
    """Every tag. One that can't be read carries its error; only an unreadable listing raises."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        repositories = client.repositories()
        listed = pool.map(client.tags, repositories)
        tags = [CatalogTag(name, tag) for name, values in zip(repositories, listed) for tag in values]
        heads = pool.map(lambda item: _attempt(lambda: client.digest(item.repository, item.tag)), tags)
        for item, (digest, error) in zip(tags, heads):
            item.digest, item.error = digest, error

        where = {item.digest: item.repository for item in tags if item.digest}
        summaries = _cached(list(where))
        missing = [digest for digest in where if digest not in summaries]
        read = list(pool.map(lambda digest: _attempt(lambda: summarize(client, where[digest], digest)), missing))
    fresh = {digest: summary for digest, (summary, _) in zip(missing, read) if summary}
    errors = {digest: error for digest, (_, error) in zip(missing, read) if error}
    _cache(fresh)
    summaries.update(fresh)
    for item in tags:
        if item.digest:
            item.summary, item.error = summaries.get(item.digest), errors.get(item.digest)
    return tags


def stored_bytes(tags: Iterable[CatalogTag]) -> int:
    """What these tags keep in the registry, each blob counted once."""
    blobs: dict[str, int] = {}
    for item in tags:
        if item.summary:
            blobs.update(item.summary.blobs)
    return sum(blobs.values())


def redact_history(command: str) -> str:
    """Hide environment values and build arguments, which build history records as they were set."""
    if match := _SETTING.match(command):
        instruction, name = match.group(1).upper(), match.group(2)
        return f"{instruction} {name}=…" if name else f"{instruction} …"
    if match := _BUILD_ARGS.match(command):
        # The arguments aren't quoted, so only what follows the last shell marker is sure to be the command.
        end = command.rfind(_SHELL)
        shown = command[end:] if end >= 0 else ""
        return f"{match.group(1) or ''}|…{shown}"
    return command


def _image(client: RegistryClient, repository: str, platform: str | None, manifest: dict) -> dict:
    descriptor = _dict(manifest.get("config"))
    config = client.config(repository, _text(descriptor.get("digest")) or "")
    settings = _dict(config.get("config"))
    labels = _dict(settings.get("Labels"))
    layers = _dicts(manifest.get("layers"))
    return {
        "platform": platform or _platform(config),
        "size": sum(_blobs(layers).values()),
        "created": _text(config.get("created")),
        "labels": {key: value for key, value in sorted(labels.items()) if isinstance(value, str)},
        "entrypoint": _strings(settings.get("Entrypoint")),
        "command": _strings(settings.get("Cmd")),
        "exposed_ports": sorted(_dict(settings.get("ExposedPorts"))),
        "user": _text(settings.get("User")),
        "working_dir": _text(settings.get("WorkingDir")),
        "layers": [{"digest": _text(item.get("digest")), "size": _size(item.get("size"))} for item in layers],
        "history": [
            {
                "created": _text(item.get("created")),
                "command": redact_history(_text(item.get("created_by")) or ""),
                "empty_layer": item.get("empty_layer") is True,
            }
            for item in _dicts(config.get("history"))
        ],
    }


def tag_detail(client: RegistryClient, repository: str, tag: str) -> dict:
    """One tag's images, one per platform. Environment values are left out: they often hold secrets."""
    digest = client.digest(repository, tag)
    top, top_size = client.manifest(repository, digest)
    images, attestations = [], 0
    for child in _children(digest, top):
        if child.attestation:
            attestations += 1
            continue
        manifest = top if child.digest == digest else client.manifest(repository, child.digest)[0]
        images.append({"digest": child.digest, **_image(client, repository, child.platform, manifest)})
    return {
        "repository": repository,
        "tag": tag,
        "digest": digest,
        "media_type": _text(top.get("mediaType")),
        "manifest_size": top_size,
        "attestations": attestations,
        "images": images,
    }
