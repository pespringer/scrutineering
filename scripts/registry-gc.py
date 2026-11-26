#!/usr/bin/env python3
"""`make registry-gc`: free the disk space of deleted tags in the bundled registry (Compose).

See docs/design/registry-management.md. In order:
1. a preflight in the API container (src/scan/registry_gc.py) stops it if a remediation is building or
   verifying, a scan of a local image is pending or running, or a container runs a build no tag keeps.
   The containers are runtime discovery's records and, read here, the ones this host's Docker runs;
2. the registry is stopped, so nothing can push during collection;
3. `registry garbage-collect --delete-untagged` runs in a one-off container on the same volume;
4. the registry is started again, whatever happened, and the space freed is printed.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time

COMPOSE = ["docker", "compose"]
CONFIG = "/etc/distribution/config.yml"
HEALTHY_WITHIN_SECONDS = 60
# The collector's last line, e.g. "106 blobs marked, 218 blobs and 124 manifests eligible for deletion".
SUMMARY = re.compile(r"\d+ blobs marked, (\d+) blobs and (\d+) manifests eligible for deletion")


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([*COMPOSE, *args], capture_output=True, text=True, check=check)


def docker(*args: str) -> str:
    """Docker's output. A container that stopped meanwhile fails the call but leaves the others in it."""
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False).stdout


def running_containers() -> list[dict]:
    """What each running container runs: the reference it was started from, and every digest of its image."""
    ids = docker("ps", "-q").split()
    if not ids:
        return []
    containers = json.loads(docker("inspect", *ids) or "[]")
    digests: dict[str, set[str]] = {}
    for image_id in {item["Image"] for item in containers}:
        # A build whose tag moved can't be inspected any more (containerd's image store); its ID still names it.
        listed = docker("image", "inspect", "--format", "{{json .RepoDigests}}", image_id).strip()
        repo_digests = json.loads(listed) if listed else []
        digests[image_id] = {image_id, *(item.rpartition("@")[2] for item in repo_digests or [])}
    return [
        {
            "name": item["Name"].lstrip("/"),
            "image_ref": item["Config"]["Image"],
            "digests": sorted(digests[item["Image"]]),
        }
        for item in containers
    ]


def stored_kib() -> int:
    """What the registry's volume holds, read from the running registry."""
    return int(compose("exec", "-T", "registry", "du", "-sk", "/var/lib/registry").stdout.split()[0])


def wait_healthy() -> bool:
    deadline = time.monotonic() + HEALTHY_WITHIN_SECONDS
    while time.monotonic() < deadline:
        container = compose("ps", "-q", "registry", check=False).stdout.strip()
        if container:
            status = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", container], capture_output=True, text=True
            ).stdout.strip()
            if status == "healthy":
                return True
        time.sleep(2)
    return False


def collect() -> subprocess.CompletedProcess:
    return compose(
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "registry",
        "registry",
        "garbage-collect",
        "--delete-untagged",
        CONFIG,
        check=False,
    )


def main() -> int:
    print("==> preflight")
    containers = json.dumps(running_containers())
    checked = subprocess.run(
        [*COMPOSE, "exec", "-T", "api", "python", "-m", "src.scan.registry_gc", "--containers", "-"],
        input=containers,
        capture_output=True,
        text=True,
    )
    if checked.returncode != 0:
        print(checked.stdout.strip() or checked.stderr.strip()[-2000:])
        print("Nothing was collected.")
        return 1
    before = stored_kib()

    print("==> stop the registry")
    compose("stop", "registry")
    result = None
    try:
        print("==> collect")
        result = collect()
    finally:
        print("==> start the registry")
        compose("start", "registry", check=False)
        healthy = wait_healthy()
    if result.returncode != 0:
        print((result.stderr or result.stdout).strip()[-2000:])
        print("Collection failed." + (" The registry is running again." if healthy else ""))
    if not healthy:
        print(f"The registry isn't healthy after {HEALTHY_WITHIN_SECONDS}s: check `docker compose logs registry`.")
    if result.returncode != 0 or not healthy:
        return 1
    after = stored_kib()
    summary = SUMMARY.search(result.stdout + result.stderr)
    removed = f"{summary.group(2)} manifests and {summary.group(1)} blobs" if summary else "unused data"
    freed = (before - after) / 1024
    print(f"Removed {removed}. The registry held {before / 1024:.1f} MiB, and now {after / 1024:.1f} MiB.")
    print(f"{freed:.1f} MiB freed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
