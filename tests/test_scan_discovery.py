import asyncio
import json
import stat

import pytest

from src.scan.discovery import ContainerdCollector, DockerRuntimeCollector
from src.scan.discovery._process import RuntimeUnavailable


def _fake_cli(tmp_path, name: str, script: str) -> str:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{script}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_docker_collector_parses_json_lines_and_skips_garbage(tmp_path):
    line = json.dumps({"ID": "abc", "Names": "web", "Image": "nginx:1.27", "State": "running", "Labels": "a=b"})
    docker = _fake_cli(tmp_path, "docker", f"echo '{line}'\necho 'not json'")
    containers = asyncio.run(DockerRuntimeCollector(docker_bin=docker).list_running_containers())
    assert containers == [
        {
            "id": "abc",
            "names": "web",
            "image": "nginx:1.27",
            "status": "running",
            "created": "",
            "ports": "",
            "labels": "a=b",
        }
    ]


def test_a_missing_binary_is_an_error_not_an_empty_list(tmp_path):
    """Discovery must tell "can't list" from "nothing running" (docs/design/runtime-discovery.md)."""
    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(RuntimeUnavailable, match="missing or timed out"):
        asyncio.run(DockerRuntimeCollector(docker_bin=missing).list_running_containers())
    with pytest.raises(RuntimeUnavailable, match="missing or timed out"):
        asyncio.run(ContainerdCollector(ctr_bin=missing).list_running_containers())
    assert asyncio.run(ContainerdCollector(ctr_bin=missing).get_container_info("x")) is None


def test_containerd_collector_lists_ids_and_reads_info(tmp_path):
    ctr = _fake_cli(
        tmp_path,
        "ctr",
        """
case "$3 $4" in
  "containers list") printf 'c1\\n\\nc2\\n' ;;
  "containers info") printf 'Image: docker.io/library/redis:7\\nRuntime: io.containerd.runc.v2\\n' ;;
esac""",
    )
    collector = ContainerdCollector(ctr_bin=ctr, namespace="k8s.io")
    assert asyncio.run(collector.list_running_containers()) == [
        {"id": "c1", "namespace": "k8s.io"},
        {"id": "c2", "namespace": "k8s.io"},
    ]
    info = asyncio.run(collector.get_container_info("c1"))
    assert info["image"] == "docker.io/library/redis:7"
    assert info["runtime"] == "io.containerd.runc.v2"


def test_a_failed_listing_reports_the_runtime_s_error(tmp_path):
    ctr = _fake_cli(tmp_path, "ctr", "echo boom >&2; exit 1")
    with pytest.raises(RuntimeUnavailable, match="^boom$"):
        asyncio.run(ContainerdCollector(ctr_bin=ctr).list_running_containers())
    docker = _fake_cli(
        tmp_path, "docker", "echo 'Cannot connect to the Docker daemon at tcp://docker-proxy:2375' >&2; exit 1"
    )
    with pytest.raises(RuntimeUnavailable, match="Cannot connect to the Docker daemon"):
        asyncio.run(DockerRuntimeCollector(docker_bin=docker).list_running_containers())


def test_docker_repo_digests_tell_pulled_images_from_local_builds(tmp_path):
    docker = _fake_cli(
        tmp_path,
        "docker",
        """
case "$5" in
  nginx:1.27) echo '["nginx@sha256:aaa"]' ;;
  myapp:dev) echo '[]' ;;
  *) echo "Error: No such image: $5" >&2; exit 1 ;;
esac""",
    )
    collector = DockerRuntimeCollector(docker_bin=docker)
    assert asyncio.run(collector.repo_digests("nginx:1.27")) == ["nginx@sha256:aaa"]
    assert asyncio.run(collector.repo_digests("myapp:dev")) == []
    assert asyncio.run(collector.repo_digests("gone:1")) is None
