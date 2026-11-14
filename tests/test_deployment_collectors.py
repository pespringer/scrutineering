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


def test_kubernetes_collector_requires_one_ready_digest():
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [{"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"}]}}]}
    collector = KubernetesCollector(runner=lambda command, timeout: json.dumps(payload))

    observation = collector.collect(namespace="security", selector="app=sentinel")

    assert observation.provider == "kubernetes"
    assert observation.observed_digest == DIGEST


def test_kubernetes_collector_rejects_mixed_rollout_digests():
    payload = {"items": [{"status": {"phase": "Running", "containerStatuses": [
        {"ready": True, "imageID": f"docker-pullable://registry/app@{DIGEST}"},
        {"ready": True, "imageID": "docker-pullable://registry/app@sha256:" + "b" * 64},
    ]}}]}
    collector = KubernetesCollector(runner=lambda command, timeout: json.dumps(payload))

    with pytest.raises(DeploymentCollectorError):
        collector.collect(namespace="security", selector="app=sentinel")


def test_collector_target_is_selected_by_publication_repository():
    target = configured_deployment_target(
        "acme/api",
        '{"acme/api":{"provider":"kubernetes","namespace":"security","selector":"app=api"}}',
    )

    assert target == {"provider": "kubernetes", "namespace": "security", "selector": "app=api"}


def test_collector_target_configuration_fails_closed():
    with pytest.raises(DeploymentCollectorError):
        configured_deployment_target("acme/api", "{}")
