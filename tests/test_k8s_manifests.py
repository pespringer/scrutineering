"""Offline checks of the Kubernetes manifests (there is no cluster in CI).

They catch what admission or the first deploy would reject: the namespace's `restricted` Pod
Security level, the ResourceQuota, Services that select nothing, settings that point at
services that don't exist, and NetworkPolicies that block a connection the loop needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

K8S = Path(__file__).resolve().parents[1] / "k8s"
NAMESPACE = "scrutineering"


def _documents() -> list[dict]:
    docs = []
    for path in sorted(K8S.rglob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc:
                doc.setdefault("metadata", {}).setdefault(
                    "namespace", NAMESPACE if doc["kind"] != "Namespace" else None
                )
                docs.append(doc)
    return docs


DOCS = _documents()


def _kind(kind: str, namespace: str | None = NAMESPACE) -> list[dict]:
    return [doc for doc in DOCS if doc["kind"] == kind and doc["metadata"].get("namespace") == namespace]


def _named(kind: str, name: str, namespace: str = NAMESPACE) -> dict:
    return next(doc for doc in _kind(kind, namespace) if doc["metadata"]["name"] == name)


def _quantity(value) -> float:
    """CPU in cores or memory in bytes."""
    text = str(value)
    units = {"m": 1e-3, "Ki": 2**10, "Mi": 2**20, "Gi": 2**30}
    for suffix, factor in units.items():
        if text.endswith(suffix):
            return float(text[: -len(suffix)]) * factor
    return float(text)


@pytest.mark.parametrize("deployment", _kind("Deployment"), ids=lambda doc: doc["metadata"]["name"])
def test_pods_meet_the_restricted_pod_security_level(deployment):
    pod = deployment["spec"]["template"]["spec"]
    context = pod.get("securityContext", {})
    assert context.get("runAsNonRoot") is True
    assert context.get("seccompProfile", {}).get("type") == "RuntimeDefault"
    for container in pod["containers"] + pod.get("initContainers", []):
        security = container.get("securityContext", {})
        assert security.get("allowPrivilegeEscalation") is False, container["name"]
        assert "ALL" in security.get("capabilities", {}).get("drop", []), container["name"]
        assert not security.get("privileged"), container["name"]
        for section in ("requests", "limits"):
            assert {"cpu", "memory"} <= set(container.get("resources", {}).get(section, {})), container["name"]
    assert not any("hostPath" in volume for volume in pod.get("volumes", []))


def test_the_resource_quota_fits_every_replica():
    hard = _named("ResourceQuota", "scrutineering-quota")["spec"]["hard"]
    totals = {key: 0.0 for key in hard}
    for deployment in _kind("Deployment"):
        replicas = deployment["spec"].get("replicas", 1)
        for container in deployment["spec"]["template"]["spec"]["containers"]:
            for section in ("requests", "limits"):
                for resource in ("cpu", "memory"):
                    totals[f"{section}.{resource}"] += replicas * _quantity(container["resources"][section][resource])
    for key, limit in hard.items():
        assert totals[key] <= _quantity(limit), f"{key}: {totals[key]} > {limit}"


def test_services_select_a_deployment():
    for service in [doc for doc in DOCS if doc["kind"] == "Service"]:
        namespace = service["metadata"]["namespace"]
        labels = [d["spec"]["template"]["metadata"]["labels"] for d in _kind("Deployment", namespace)]
        selector = service["spec"]["selector"]
        assert any(selector.items() <= pod.items() for pod in labels), service["metadata"]["name"]


def _service_host(host: str) -> tuple[str, str, int]:
    match = re.fullmatch(r"(?:tcp://)?([a-z0-9-]+)\.([a-z0-9-]+)\.svc\.cluster\.local:(\d+)", host)
    assert match, f"{host} must be a full service DNS name, reachable from every namespace"
    return match.group(1), match.group(2), int(match.group(3))


def test_buildkit_and_the_registry_are_where_the_settings_say():
    config = _named("ConfigMap", "scrutineering-config")["data"]
    for key in ("BUILDKIT_HOST", "LOCAL_REGISTRY_HOST"):
        name, namespace, port = _service_host(config[key])
        service = _named("Service", name, namespace)
        assert port in [item["port"] for item in service["spec"]["ports"]], key
    buildkit = _named("Deployment", "buildkitd", "scrutineering-buildkit")["spec"]["template"]["spec"]
    assert buildkit["securityContext"]["runAsNonRoot"] is True
    assert not buildkit["containers"][0].get("securityContext", {}).get("privileged")
    assert "--oci-worker-no-process-sandbox" in buildkit["containers"][0]["args"]


def test_worker_and_beat_run_the_app_that_registers_the_tasks():
    worker = _named("Deployment", "scrutineering-worker")["spec"]["template"]["spec"]["containers"][0]
    assert "command" not in worker  # the image runs `celery --app=src.scan.tasks:app worker` on CELERY_QUEUES
    assert {"name": "HOME", "value": "/tmp"} in worker["env"]
    beat = _named("Deployment", "scrutineering-celery-beat")["spec"]["template"]["spec"]["containers"][0]
    assert "--app=src.scan.tasks:app" in beat["command"] and "beat" in beat["command"]
    queues = _named("ConfigMap", "scrutineering-config")["data"]["CELERY_QUEUES"].split(",")
    assert {"scan.high", "scan.normal", "scan.low", "remediation.normal", "notify"} <= set(queues)


def _matches(peer: dict, namespace: str, labels: dict, source_namespace: str) -> bool:
    pod_ok = peer.get("podSelector", {}).get("matchLabels", {}).items() <= labels.items()
    if "namespaceSelector" in peer:
        wanted = peer["namespaceSelector"].get("matchLabels", {}).get("kubernetes.io/metadata.name")
        return pod_ok and wanted in (None, namespace)
    return ("podSelector" in peer) and pod_ok and namespace == source_namespace


def _allows(policies, direction, own_ns, own_labels, peer_ns, peer_labels, port) -> bool:
    for policy in policies:
        spec = policy["spec"]
        if policy["metadata"]["namespace"] != own_ns:
            continue
        if not spec["podSelector"].get("matchLabels", {}).items() <= own_labels.items():
            continue
        for rule in spec.get(direction, []):
            ports = [item["port"] for item in rule.get("ports", [])]
            peers = rule.get("to" if direction == "egress" else "from")
            if (not ports or port in ports) and (
                peers is None or any(_matches(peer, peer_ns, peer_labels, own_ns) for peer in peers)
            ):
                return True
    return False


CONNECTIONS = [
    ("scrutineering-dashboard", "scrutineering-api", 8000),
    ("scrutineering-api", "postgres", 5432),
    ("scrutineering-api", "redis", 6379),
    ("scrutineering-api", "scrutineering-registry", 5000),
    ("scrutineering-worker", "postgres", 5432),
    ("scrutineering-worker", "redis", 6379),
    ("scrutineering-worker", "scrutineering-registry", 5000),
    ("scrutineering-worker", "buildkitd", 1234),
    ("scrutineering-celery-beat", "postgres", 5432),
    ("scrutineering-celery-beat", "redis", 6379),
    ("buildkitd", "scrutineering-registry", 5000),
]


@pytest.mark.parametrize(("source", "target", "port"), CONNECTIONS, ids=lambda item: str(item))
def test_network_policies_allow_the_loop(source, target, port):
    policies = [doc for doc in DOCS if doc["kind"] == "NetworkPolicy"]
    pods = {
        doc["spec"]["template"]["metadata"]["labels"]["app"]: (
            doc["metadata"]["namespace"],
            doc["spec"]["template"]["metadata"]["labels"],
        )
        for doc in DOCS
        if doc["kind"] == "Deployment"
    }
    (source_ns, source_labels), (target_ns, target_labels) = pods[source], pods[target]
    assert _allows(policies, "egress", source_ns, source_labels, target_ns, target_labels, port), "egress"
    assert _allows(policies, "ingress", target_ns, target_labels, source_ns, source_labels, port), "ingress"


def test_the_registry_is_pinned_and_keeps_its_debug_port_to_itself():
    """Compose and Kubernetes run the same exact 3.x: deleting one tag needs it (docs/design/registry-management.md)."""
    container = _named("Deployment", "scrutineering-registry")["spec"]["template"]["spec"]["containers"][0]
    assert re.fullmatch(r"registry:3\.\d+\.\d+", container["image"])
    environment = {item["name"]: item["value"] for item in container["env"]}
    compose = yaml.safe_load((K8S.parent / "docker-compose.yml").read_text())["services"]["registry"]
    assert compose["image"] == container["image"]
    for settings in (environment, dict(item.split("=", 1) for item in compose["environment"])):
        assert settings["REGISTRY_HTTP_DEBUG_ADDR"].startswith("127.0.0.1:")
        assert "true" in settings["REGISTRY_STORAGE_DELETE_ENABLED"]
