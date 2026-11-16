"""Registry credentials and tag-to-digest resolution for the scan worker.

Credentials come from explicit environment settings; a partial pair is an
error rather than a silent fall back to anonymous access. Digest resolution
uses the OCI distribution API and answers the standard `WWW-Authenticate`
challenge, so public Docker Hub and GHCR images resolve without credentials.
"""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from src.scan.image_identity import ImageIdentity

_MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
_DOCKER_HUB_HOSTS = {"registry-1.docker.io", "docker.io", "index.docker.io"}
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")

Credentials = tuple[str, str]


def registry_credentials_from_env(env: Mapping[str, str] | None = None) -> dict[str, Credentials]:
    """Return explicitly configured registry credentials, keyed by registry.

    Partial credential pairs are rejected so a deployment cannot silently fall
    back to anonymous access after a configuration typo.
    """
    values = os.environ if env is None else env
    credentials: dict[str, Credentials] = {}
    docker_user, docker_password = values.get("DOCKERHUB_USERNAME", ""), values.get("DOCKERHUB_PASSWORD", "")
    if bool(docker_user) != bool(docker_password):
        raise ValueError("DOCKERHUB_USERNAME and DOCKERHUB_PASSWORD must be configured together")
    if docker_user:
        credentials["dockerhub"] = (docker_user, docker_password)
    if bool(values.get("AWS_ACCESS_KEY_ID", "")) != bool(values.get("AWS_SECRET_ACCESS_KEY", "")):
        # Not used here (the scanners read AWS credentials directly), but a half-configured pair is an error.
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be configured together")
    if values.get("GITHUB_TOKEN"):
        credentials["ghcr.io"] = (values.get("GITHUB_USERNAME", "gh_token"), values["GITHUB_TOKEN"])
    gitlab_token = values.get("GITLAB_TOKEN") or values.get("CI_JOB_TOKEN")
    if gitlab_token:
        credentials["gitlab"] = (values.get("GITLAB_USERNAME", "gitlab-ci-token"), gitlab_token)
    raw = str(values.get("REGISTRY_CREDENTIALS_JSON", "")).strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("REGISTRY_CREDENTIALS_JSON must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("REGISTRY_CREDENTIALS_JSON must map registry hosts to credentials")
        for host, entry in parsed.items():
            if not isinstance(entry, dict) or not entry.get("username") or not entry.get("password"):
                raise ValueError(f"REGISTRY_CREDENTIALS_JSON[{host!r}] needs a username and password")
            credentials[str(host)] = (str(entry["username"]), str(entry["password"]))
    return credentials


def registry_env_keys(registry: str) -> tuple[str, ...]:
    return {
        "dockerhub": ("DOCKERHUB_USERNAME", "DOCKERHUB_PASSWORD"),
        "ghcr.io": ("GITHUB_TOKEN",),
        "gitlab": ("GITLAB_TOKEN", "CI_JOB_TOKEN"),
    }.get(registry, ("REGISTRY_CREDENTIALS_JSON",))


def credentials_for_host(host: str, env: Mapping[str, str] | None = None) -> Credentials | None:
    """Credentials for one registry host. Explicit `REGISTRY_CREDENTIALS_JSON` entries win.

    ECR and GCR are not listed: Trivy and Grype authenticate to them directly
    from the standard AWS and Google credentials in the worker environment.
    """
    configured = registry_credentials_from_env(env)
    if host in configured:
        return configured[host]
    if host in _DOCKER_HUB_HOSTS:
        return configured.get("dockerhub")
    if host == "registry.gitlab.com":
        return configured.get("gitlab")
    return None


def _basic(credentials: Credentials) -> str:
    return "Basic " + base64.b64encode(f"{credentials[0]}:{credentials[1]}".encode()).decode()


def _challenge_params(header: str) -> tuple[str, dict[str, str]]:
    scheme, _, rest = header.partition(" ")
    return scheme.lower(), dict(re.findall(r'(\w+)="([^"]*)"', rest))


def _authorization(challenge: str, credentials: Credentials | None, opener: Callable) -> str:
    """Answer a registry `WWW-Authenticate` challenge with a Basic or Bearer header."""
    scheme, params = _challenge_params(challenge)
    if scheme == "basic":
        if credentials is None:
            raise PermissionError("registry requires credentials")
        return _basic(credentials)
    if scheme != "bearer" or not params.get("realm", "").startswith(("https://", "http://")):
        raise PermissionError(f"unsupported registry auth challenge: {challenge[:120]}")
    query = {key: params[key] for key in ("service", "scope") if key in params}
    headers = {"Authorization": _basic(credentials)} if credentials else {}
    with opener(Request(f"{params['realm']}?{urlencode(query)}", headers=headers), timeout=15) as response:
        body = json.loads(response.read().decode())
    token = body.get("token") or body.get("access_token")
    if not token:
        raise PermissionError("registry token endpoint returned no token")
    return f"Bearer {token}"


def resolve_digest(
    identity: ImageIdentity,
    *,
    credentials: Credentials | None = None,
    scheme: str = "https",
    opener: Callable = urlopen,
) -> str:
    """Resolve an image tag to its immutable `sha256:` digest through the registry API."""
    if identity.digest:
        return identity.digest
    if scheme not in {"http", "https"}:
        raise ValueError("registry scheme must be http or https")
    if any(part in {".", ".."} for part in identity.repository.split("/")):
        raise ValueError("invalid repository path")
    url = f"{scheme}://{identity.host}/v2/{identity.repository}/manifests/{identity.tag}"

    def head(authorization: str | None):
        headers = {"Accept": _MANIFEST_TYPES}
        if authorization:
            headers["Authorization"] = authorization
        return opener(Request(url, headers=headers, method="HEAD"), timeout=15)

    try:
        response = head(None)
    except HTTPError as error:
        if error.code != 401:
            raise
        response = head(_authorization(error.headers.get("WWW-Authenticate", ""), credentials, opener))
    with response:
        digest = response.headers.get("Docker-Content-Digest", "")
    if not _DIGEST.fullmatch(digest):
        raise RuntimeError("registry did not return an immutable sha256 digest")
    return digest
