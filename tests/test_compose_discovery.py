"""Runtime discovery reaches Docker only through the read-only proxy (docs/design/runtime-discovery.md).

The Docker socket is root on the host. These checks keep it out of every service but `docker-proxy`,
mounted read-only, with writes refused and the proxy reachable by the worker alone.
"""

from pathlib import Path

import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]


def _env(service: str) -> dict[str, str]:
    return dict(item.split("=", 1) for item in SERVICES[service].get("environment", []))


def test_only_the_proxy_mounts_the_docker_socket_and_only_read_only():
    mounts = {
        name: [volume for volume in service.get("volumes", []) if "docker.sock" in volume]
        for name, service in SERVICES.items()
    }
    assert {name for name, found in mounts.items() if found} == {"docker-proxy"}
    [mount] = mounts["docker-proxy"]
    assert mount.endswith(":/var/run/docker.sock:ro")
    assert not any("docker.sock" in str(service.get("environment", "")) for service in SERVICES.values())


def test_the_proxy_allows_listing_and_refuses_writes():
    env = _env("docker-proxy")
    assert env["POST"] == "0" and env["CONTAINERS"] == "1" and env["IMAGES"] == "1"
    for name in ("EXEC", "BUILD", "VOLUMES", "NETWORKS", "SERVICES", "SECRETS", "ALLOW_START"):
        assert env.get(name, "0") == "0", name
    proxy = SERVICES["docker-proxy"]
    assert proxy["read_only"] is True and proxy["cap_drop"] == ["ALL"]
    assert "ports" not in proxy


def test_only_the_worker_can_reach_the_proxy():
    assert COMPOSE["networks"]["discovery"]["internal"] is True
    on_discovery = {name for name, service in SERVICES.items() if "discovery" in service.get("networks", [])}
    assert on_discovery == {"docker-proxy", "celery-worker"}
    assert SERVICES["docker-proxy"]["networks"] == ["discovery"]
    assert _env("celery-worker")["DOCKER_HOST"] == "tcp://docker-proxy:2375"
