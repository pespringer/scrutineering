"""Container registry authentication and image pulling utilities.

Supports: Docker Hub, AWS ECR, GCP GCR/A, GitHub GHCR, GitLab, Harbor, Quay.
"""

import asyncio
import base64
import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)


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


async def login_ecr(region: Optional[str] = None) -> tuple[str, str]:
    """Get ECR login credentials via AWS CLI.

    Returns (username, password) where password is the auth token.
    """
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
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"AWS ECR login failed: {stderr.decode()}")
        return "AWS", stdout.decode().strip()
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
    with open(key_path) as f:
        key_json = json.load(f)

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
        user = os.environ.get("DOCKERHUB_USERNAME")
        pwd = os.environ.get("DOCKERHUB_PASSWORD")
        if user and pwd:
            return (user, pwd)
        return None
    elif registry == "gitlab":
        user = os.environ.get("GITLAB_USERNAME", "gitlab-ci-token")
        pwd = os.environ.get("GITLAB_TOKEN", os.environ.get("CI_JOB_TOKEN", ""))
        if pwd:
            return (user, pwd)
        return None
    else:
        auth_fn = dispatch.get(registry)
        if auth_fn:
            return await auth_fn(**kwargs)

    return None


async def docker_pull(image_name: str) -> str:
    """Pull a container image using Docker.

    Returns stdout from docker pull.
    Raises RuntimeError if the pull fails.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", image_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"docker pull failed for '{image_name}': "
                f"{stderr.decode(errors='replace')[:500]}"
            )
        return stdout.decode(errors="replace")
    except FileNotFoundError:
        raise RuntimeError("Docker is not installed or not in PATH.")
