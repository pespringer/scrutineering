"""Provider-neutral deployment observation adapters.

Collectors return only facts resolved from the deployment runtime. They never
accept a mutable tag as a digest and fail closed when a workload is mixed,
unready, or missing immutable image identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping


DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class DeploymentCollectorError(RuntimeError):
    """Raised when a deployment runtime cannot provide trustworthy evidence."""


@dataclass(frozen=True)
class DeploymentObservation:
    target: str
    provider: str
    observed_digest: str
    rollout_status: str
    source: str
    observed_at: str
    evidence_fingerprint: str

    @classmethod
    def create(cls, *, target: str, provider: str, observed_digest: str,
               rollout_status: str, source: str,
               observed_at: str | None = None) -> "DeploymentObservation":
        if not target or any(char.isspace() for char in target):
            raise ValueError("deployment target is invalid")
        if not DIGEST_PATTERN.fullmatch(observed_digest):
            raise ValueError("deployment observation requires an immutable digest")
        if rollout_status not in {"ready", "degraded", "unavailable"}:
            raise ValueError("deployment rollout status is invalid")
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        canonical = json.dumps({
            "target": target, "provider": provider,
            "observed_digest": observed_digest,
            "rollout_status": rollout_status, "source": source,
            "observed_at": timestamp,
        }, sort_keys=True, separators=(",", ":"))
        return cls(target, provider, observed_digest, rollout_status, source,
                   timestamp, hashlib.sha256(canonical.encode()).hexdigest())


def _default_runner(command: list[str], timeout: int) -> str:
    try:
        completed = subprocess.run(command, check=True, capture_output=True,
                                   text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DeploymentCollectorError(f"deployment command failed: {exc}") from exc
    return completed.stdout


def _kubernetes_command(namespace: str, selector: str) -> list[str]:
    """Build kubectl arguments for kubeconfig or standard in-cluster auth."""
    command = [
        "kubectl", "get", "pods", "--namespace", namespace,
        "--selector", selector, "--output", "json",
    ]
    token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    if host and token_path.is_file() and ca_path.is_file():
        token = token_path.read_text(encoding="utf-8").strip()
        if token:
            command[1:1] = [
                f"--server=https://{host}:{port}",
                f"--certificate-authority={ca_path}",
                f"--token={token}",
            ]
    return command


class DockerComposeCollector:
    """Resolve a running Docker container's immutable image digest."""

    provider = "docker"

    def __init__(self, runner: Callable[[list[str], int], str] = _default_runner,
                 timeout_seconds: int = 15):
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("collector timeout is out of bounds")
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def collect(self, container: str) -> DeploymentObservation:
        raw = self.runner(["docker", "inspect", container], self.timeout_seconds)
        try:
            record = json.loads(raw)[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise DeploymentCollectorError("docker returned an invalid inspect payload") from exc
        state = record.get("State") or {}
        if not state.get("Running"):
            raise DeploymentCollectorError("docker container is not running")
        health = (state.get("Health") or {}).get("Status")
        if health in {"starting", "unhealthy"}:
            raise DeploymentCollectorError(f"docker container health is {health}")
        if health and health != "healthy":
            raise DeploymentCollectorError("docker container returned an invalid health status")
        digest = str(record.get("Image") or "")
        if not DIGEST_PATTERN.fullmatch(digest):
            repo_digests = record.get("RepoDigests") or []
            digest = next((item.rsplit("@", 1)[-1] for item in repo_digests if "@" in item), "")
        if not DIGEST_PATTERN.fullmatch(digest):
            raise DeploymentCollectorError("docker container has no immutable image digest")
        return DeploymentObservation.create(
            target=container, provider=self.provider, observed_digest=digest,
            rollout_status="ready", source="docker inspect",
        )


class KubernetesCollector:
    """Resolve one consistent, ready image digest from a Kubernetes selector."""

    provider = "kubernetes"

    def __init__(self, runner: Callable[[list[str], int], str] = _default_runner,
                 timeout_seconds: int = 20):
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("collector timeout is out of bounds")
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def collect(self, *, namespace: str, selector: str) -> DeploymentObservation:
        if not namespace or not selector or any(char.isspace() for char in namespace):
            raise ValueError("kubernetes target is invalid")
        raw = self.runner(_kubernetes_command(namespace, selector), self.timeout_seconds)
        try:
            payload = json.loads(raw)
            pods = payload["items"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise DeploymentCollectorError("kubectl returned an invalid pod payload") from exc
        if not pods:
            raise DeploymentCollectorError("kubernetes selector returned no pods")
        digests: set[str] = set()
        for pod in pods:
            status = pod.get("status") or {}
            if status.get("phase") != "Running":
                raise DeploymentCollectorError("kubernetes workload is not fully running")
            containers = status.get("containerStatuses") or []
            if not containers or not all(container.get("ready") for container in containers):
                raise DeploymentCollectorError("kubernetes workload is not ready")
            digests.update(
                str(container.get("imageID", "")).removeprefix("docker-pullable://").rsplit("@", 1)[-1]
                for container in containers
            )
        digests.discard("")
        if len(digests) != 1 or not DIGEST_PATTERN.fullmatch(next(iter(digests), "")):
            raise DeploymentCollectorError("kubernetes workload does not have one immutable image digest")
        return DeploymentObservation.create(
            target=f"{namespace}/{selector}", provider=self.provider,
            observed_digest=next(iter(digests)), rollout_status="ready",
            source="kubectl pod status",
        )


def observation_payload(observation: DeploymentObservation) -> Mapping[str, Any]:
    """Return a redaction-safe payload suitable for audit or API transport."""
    return {
        "target": observation.target, "provider": observation.provider,
        "observed_digest": observation.observed_digest,
        "rollout_status": observation.rollout_status,
        "source": observation.source, "observed_at": observation.observed_at,
        "evidence_fingerprint": observation.evidence_fingerprint,
    }
