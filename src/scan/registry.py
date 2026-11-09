"""Container registry authentication and image pulling utilities.

Supports: Docker Hub, AWS ECR, GCP GCR/A, GitHub GHCR, GitLab, Harbor, Quay.
"""

import asyncio
import base64
import json
import logging
import os
import re
from urllib.request import Request, urlopen
from typing import Optional

logger = logging.getLogger(__name__)


def registry_credentials_from_env(env: dict[str, str] | None = None) -> dict[str, tuple[str, str]]:
    """Return explicitly configured registry credentials without exposing secrets."""
    values = env or os.environ
    credentials: dict[str, tuple[str, str]] = {}
    if values.get("DOCKERHUB_USERNAME") and values.get("DOCKERHUB_PASSWORD"):
        credentials["dockerhub"] = (values["DOCKERHUB_USERNAME"], values["DOCKERHUB_PASSWORD"])
    if values.get("GITHUB_TOKEN"):
        credentials["ghcr.io"] = ("gh_token", values["GITHUB_TOKEN"])
    if values.get("GITLAB_TOKEN") or values.get("CI_JOB_TOKEN"):
        credentials["gitlab"] = (values.get("GITLAB_USERNAME", "gitlab-ci-token"), values.get("GITLAB_TOKEN", values.get("CI_JOB_TOKEN", "")))
    return credentials


def registry_env_keys(registry: str) -> tuple[str, ...]:
    return {
        "dockerhub": ("DOCKERHUB_USERNAME", "DOCKERHUB_PASSWORD"),
        "ghcr.io": ("GITHUB_TOKEN",),
        "gitlab": ("GITLAB_TOKEN", "CI_JOB_TOKEN"),
        "ecr": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        "gcr.io": ("GOOGLE_APPLICATION_CREDENTIALS",),
    }.get(registry, ())


def resolve_registry_digest(
    registry: str,
    repository: str,
    reference: str,
    *,
    token: str | None = None,
    opener=urlopen,
) -> str:
    """Resolve a tag through the OCI Registry v2 manifest API."""
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", registry) or not repository or not reference:
        raise ValueError("invalid registry image coordinates")
    if any(part in {".", ".."} for part in repository.split("/")):
        raise ValueError("invalid repository path")
    url = f"https://{registry}/v2/{repository}/manifests/{reference}"
    headers = {"Accept": ", ".join([
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ])}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = opener(Request(url, headers=headers, method="HEAD"))
    digest = response.headers.get("Docker-Content-Digest")
    if not digest or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise RuntimeError("registry did not return an immutable sha256 digest")
    return digest


def detect_registry(image_name: str) -> str:
    """Detect the registry from an image reference string.

    Examples:
        'nginx:latest'                  -> 'dockerhub'
        'ghcr.io/user/app:v1'           -> 'ghcr.io'
        '123456789.dkr.ecr.us-east-1.amazonaws.com/my/app:v1' -> 'ecr'
        'gcr.io/project/img:v1'         -> 'gcr.io'
        'harbor.company.com/proj/img:v1' -> 'harbor.company.com'
    """
    # Docker Hub (no host prefix, or library/ prefix)
    if "/" not in image_name or image_name.startswith("library/"):
        return "dockerhub"

    first_part = image_name.split("/")[0]

    # ECR
    if re.match(r"\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com", first_part):
        return "ecr"

    # GitHub Container Registry
    if first_part == "ghcr.io":
        return "ghcr.io"

    # GCR
    if first_part in ("gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"):
        return first_part

    # GitLab
    if "gitlab" in first_part.lower() or first_part == "registry.gitlab.com":
        return "gitlab"

    # Harbor / private registry (contains a dot but not a known public one)
    if "." in first_part:
        if first_part.endswith("harbor") or "harbor" in first_part.lower():
            return "harbor"
        return first_part  # Treat as private registry host

    # Default: Docker Hub
    return "dockerhub"


async def login_ecr(region: Optional[str] = None, timeout_seconds: int = 60) -> tuple[str, str]:
    """Get ECR login credentials via AWS CLI.

    Returns (username, password) where password is the auth token.
    """
    if timeout_seconds < 1: raise ValueError("timeout_seconds must be positive")
    if region is not None and not re.fullmatch(r"[a-z0-9-]{1,32}", region):
        raise ValueError("AWS region contains invalid characters")
    args = ["aws", "ecr", "get-login-password"]
    if region:
        args.extend(["--region", region])

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        if proc.returncode != 0:
            raise RuntimeError(f"AWS ECR login failed: {stderr.decode()}")
        return "AWS", stdout.decode().strip()
    except asyncio.TimeoutError as exc:
        proc.kill(); await proc.communicate()
        raise RuntimeError("AWS ECR login timed out") from exc
    except FileNotFoundError:
        raise RuntimeError("AWS CLI not installed. Install awscli to use ECR registries.")


async def login_gcr(service_account_key_path: Optional[str] = None) -> tuple[str, str]:
    """Authenticate to GCR using a service account key.

    Returns (username, password) for docker login.
    """
    key_path = service_account_key_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not key_path or not os.path.exists(key_path):
        raise RuntimeError(
            "GCR authentication requires GOOGLE_APPLICATION_CREDENTIALS "
            "or a service_account_key_path to be set."
        )

    # Use the _json_key_base64 auth method
    try:
        with open(key_path) as f:
            key_json = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("GCR credentials are not valid JSON") from exc

    username = "_json_key_base64"
    password = base64.b64encode(json.dumps(key_json).encode()).decode()
    return username, password


async def login_ghcr(token: Optional[str] = None) -> tuple[str, str]:
    """Authenticate to GitHub Container Registry.

    Returns (username, password) for docker login.
    """
    gh_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not gh_token:
        raise RuntimeError("GITHUB_TOKEN environment variable required for GHCR access.")
    return "gh_token", gh_token


async def login_harbor(harbor_url: str, username: str, password: str) -> tuple[str, str]:
    """Authenticate to Harbor registry."""
    return username, password


async def authenticate_to_registry(registry: str, **kwargs) -> Optional[tuple[str, str]]:
    """Get credentials for a given registry type.

    Returns (username, password) tuple or None if no auth needed.

    Supported registries: dockerhub, ecr, gcr.io, ghcr.io, harbor, gitlab
    """
    dispatch = {
        "ecr": login_ecr,
        "gcr.io": login_gcr,
        "ghcr.io": login_ghcr,
        "harbor": lambda **k: login_harbor(
            kwargs.get("harbor_url", ""),
            kwargs.get("username", ""),
            kwargs.get("password", ""),
        ),
    }

    if registry == "dockerhub":
        # Docker Hub uses DOCKERHUB_USERNAME / DOCKERHUB_PASSWORD env vars
        return registry_credentials_from_env().get("dockerhub")
    elif registry == "gitlab":
        return registry_credentials_from_env().get("gitlab")
    else:
        auth_fn = dispatch.get(registry)
        if auth_fn:
            return await auth_fn(**kwargs)

    return None


async def docker_pull(image_name: str, timeout_seconds: int = 1800) -> str:
    """Pull a container image using Docker.

    Returns stdout from docker pull.
    Raises RuntimeError if the pull fails.
    """
    if timeout_seconds < 1: raise ValueError("timeout_seconds must be positive")
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", image_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        if proc.returncode != 0:
            raise RuntimeError(
                f"docker pull failed for '{image_name}': "
                f"{stderr.decode(errors='replace')[:500]}"
            )
        return stdout.decode(errors="replace")
    except asyncio.TimeoutError as exc:
        proc.kill(); await proc.communicate()
        raise RuntimeError("docker pull timed out") from exc
    except FileNotFoundError:
        raise RuntimeError("Docker is not installed or not in PATH.")


async def resolve_image_digest(image_name: str, docker_bin: str = "docker") -> str:
    """Resolve a local image reference to its immutable ``sha256`` digest."""
    if "@sha256:" in image_name:
        digest = image_name.rsplit("@", 1)[1]
        if re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            return digest
        raise ValueError("image digest must use a 64-character sha256 value")

    try:
        proc = await asyncio.create_subprocess_exec(
            docker_bin, "image", "inspect", image_name,
            "--format", "{{index .RepoDigests 0}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
    except FileNotFoundError as exc:
        raise RuntimeError("Docker is not installed or not in PATH.") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"could not resolve image digest: {stderr.decode(errors='replace')[:500]}")

    resolved = stdout.decode(errors="replace").strip()
    digest = resolved.rsplit("@", 1)[-1]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise RuntimeError(f"docker returned no immutable digest for '{image_name}'")
    return digest


async def resolve_image_digest_with_fallback(image_name: str, token: str | None = None) -> str:
    """Try the local daemon, then resolve through the OCI Registry API."""
    try:
        return await resolve_image_digest(image_name)
    except Exception as local_error:
        from src.scan.image_identity import parse_image_reference
        identity = parse_image_reference(image_name)
        host = "registry-1.docker.io" if identity.registry.value == "dockerhub" else identity.registry.value
        repository = identity.repo_name
        if host == "registry-1.docker.io" and "/" not in repository:
            repository = f"library/{repository}"
        try:
            return await asyncio.to_thread(resolve_registry_digest, host, repository, identity.tag, token=token)
        except Exception as remote_error:
            raise RuntimeError(f"local and remote digest resolution failed: {local_error}; {remote_error}") from remote_error
