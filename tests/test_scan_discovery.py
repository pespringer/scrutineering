import asyncio
import json
import stat

from src.scan.discovery import ContainerdCollector, DockerRuntimeCollector


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


def test_missing_binaries_return_no_containers(tmp_path):
    missing = str(tmp_path / "does-not-exist")
    assert asyncio.run(DockerRuntimeCollector(docker_bin=missing).list_running_containers()) == []
    assert asyncio.run(ContainerdCollector(ctr_bin=missing).list_running_containers()) == []
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


def test_containerd_list_failure_returns_no_containers(tmp_path):
    ctr = _fake_cli(tmp_path, "ctr", "echo boom >&2; exit 1")
    assert asyncio.run(ContainerdCollector(ctr_bin=ctr).list_running_containers()) == []
