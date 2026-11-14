import json

import pytest

from src.remediation.deployment_collectors import (
    DeploymentCollectorError,
    DockerComposeCollector,
    KubernetesCollector,
    observation_payload,
)
from src.remediation.deployment_tasks import configured_deployment_target


DIGEST = "sha256:" + "a" * 64


def test_docker_collector_returns_running_immutable_digest():
    collector = DockerComposeCollector(
        runner=lambda command, timeout: json.dumps([{"Image": DIGEST, "State": {"Running": True}}])
    )

    observation = collector.collect("scrutineering-api")

    assert observation.observed_digest == DIGEST
    assert observation.rollout_status == "ready"
    assert observation_payload(observation)["evidence_fingerprint"] == observation.evidence_fingerprint


def test_docker_collector_rejects_stopped_or_mutable_container():
    collector = DockerComposeCollector(
        runner=lambda command, timeout: json.dumps([{"Image": "latest", "State": {"Running": False}}])
    )

    with pytest.raises(DeploymentCollectorError):
        collector.collect("scrutineering-api")


@pytest.mark.parametrize("health", ["starting", "unhealthy"])
def test_docker_collector_requires_healthy_container(health):
    collector = DockerComposeCollector(
        runner=lambda command, timeout: json.dumps([{
            "Image": DIGEST,
            "State": {"Running": True, "Health": {"Status": health}},
        }])
    )

    with pytest.raises(DeploymentCollectorError, match=f"health is {health}"):
        collector.collect("scrutineering-api")


def test_docker_collector_accepts_healthy_container():
    collector = DockerComposeCollector(
        runner=lambda command, timeout: json.dumps([{
            "Image": DIGEST,
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }])
    )

    assert collector.collect("scrutineering-api").rollout_status == "ready"


def test_kubernetes_collector_requires_one_ready_digest():
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [{"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"}]}}]}
    collector = KubernetesCollector(runner=lambda command, timeout: json.dumps(payload))

    observation = collector.collect(namespace="security", selector="app=sentinel")

    assert observation.provider == "kubernetes"
    assert observation.observed_digest == DIGEST


def test_kubernetes_collector_verifies_deployment_rollout_before_pods():
    commands = []
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [
        {"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"},
    ]}}]}

    def runner(command, timeout):
        commands.append(command)
        return "deployment successfully rolled out" if command[1] == "rollout" else json.dumps(payload)

    observation = KubernetesCollector(runner=runner).collect(
        namespace="security", selector="app=sentinel", workload="sentinel",
    )

    assert commands[0] == [
        "kubectl", "rollout", "status", "deployment/sentinel",
        "--namespace", "security", "--timeout=20s",
    ]
    assert observation.target == "security/sentinel"
    assert observation.source == "kubectl rollout status and pod status"


def test_kubernetes_collector_rejects_mixed_rollout_digests():
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [
        {"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"},
        {"ready": True, "imageID": "docker-pullable://registry/app@sha256:" + "b" * 64},
    ]}}]}
    collector = KubernetesCollector(runner=lambda command, timeout: json.dumps(payload))

    with pytest.raises(DeploymentCollectorError):
        collector.collect(namespace="security", selector="app=sentinel")


def test_kubernetes_collector_uses_standard_in_cluster_service_account(tmp_path, monkeypatch):
    token_path = tmp_path / "token"
    ca_path = tmp_path / "ca.crt"
    token_path.write_text("test-token", encoding="utf-8")
    ca_path.write_text("ca", encoding="utf-8")
    paths = {
        "/var/run/secrets/kubernetes.io/serviceaccount/token": token_path,
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt": ca_path,
    }
    monkeypatch.setattr(
        "src.remediation.deployment_collectors.Path",
        lambda value: paths[value],
    )
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT_HTTPS", "6443")
    command_seen = []
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [
        {"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"},
    ]}}]}
    collector = KubernetesCollector(
        runner=lambda command, timeout: command_seen.append(command) or json.dumps(payload)
    )

    collector.collect(namespace="security", selector="app=sentinel")

    assert "--server=https://10.0.0.1:6443" in command_seen[0]
    assert f"--certificate-authority={ca_path}" in command_seen[0]
    assert "--token=test-token" in command_seen[0]


def test_collector_target_is_selected_by_publication_repository():
    target = configured_deployment_target(
        "acme/api",
        '{"acme/api":{"provider":"kubernetes","namespace":"security","selector":"app=api"}}',
    )

    assert target == {"provider": "kubernetes", "namespace": "security", "selector": "app=api"}


def test_collector_target_configuration_fails_closed():
    with pytest.raises(DeploymentCollectorError):
        configured_deployment_target("acme/api", "{}")


def test_kubernetes_target_accepts_optional_workload_name():
    target = configured_deployment_target(
        "acme/api",
        '{"acme/api":{"provider":"kubernetes","namespace":"security","selector":"app=api","workload":"api"}}',
    )

    assert target["workload"] == "api"
