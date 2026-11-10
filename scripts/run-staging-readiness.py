"""Exercise the production boundaries with deterministic staging doubles."""

import asyncio
import json
import tempfile
from pathlib import Path
import time
import os

os.environ.setdefault("SCRUTINEERING_TEST_MODE", "1")

from sqlalchemy import create_engine, inspect

from src.api.app import is_service_request_authorized
from src.api.service_auth import create_replay_guard, sign_service_request
from src.db.models import Base
from src.forensics.audit import AuditEvent, AuditLogger
from src.forensics.audit_anchor import AuditAnchor
from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.event_store import JsonlEventStore
from src.runtime.managed_delivery import ManagedEventQueue
from src.runtime.replay_checkpoint import ReplayCheckpoint
from src.scan.evidence import build_evidence, verify_release_evidence
from src.scan.redis_cache import RedisScanCache


class FakeRedis:
    def __init__(self):
        self.values = {}

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, ex):
        self.values[key] = value


class FakeEvidenceVerifier:
    def __init__(self, **kwargs):
        self.policy = kwargs["policy"]

    def __call__(self, envelope, _artifact):
        return envelope["signature"]["identity"] == self.policy["identity"]


def main():
    engine = create_engine("sqlite:///:memory:")
    # SQLite does not provide PostgreSQL's char_length() used by the model
    # constraints. Register the equivalent function so schema creation remains
    # a meaningful, deterministic model smoke test.
    with engine.connect() as connection:
        connection.connection.create_function("char_length", 1, len)
    Base.metadata.create_all(engine)
    tables = set(inspect(engine).get_table_names())
    assert {"audit_log", "audit_chain_anchors", "remediation_events"} <= tables
    print("PASS staging database schema and migration targets")

    body = b'{"scan":"staging"}'
    headers = sign_service_request("staging-scanner", body, "staging-secret", int(time.time()))
    guard = create_replay_guard()
    assert is_service_request_authorized(headers, body, "staging-secret", guard)
    assert not is_service_request_authorized(headers, body, "staging-secret", guard)
    print("PASS authenticated service request and replay blocking")

    async def exercise_async_boundaries():
        cache = RedisScanCache(FakeRedis(), ttl_seconds=60)
        await cache.set("trivy", "alpine@sha256:" + "a" * 64, [{"cve_id": "CVE-STAGING"}])
        assert await cache.get("trivy", "alpine@sha256:" + "a" * 64)
        with tempfile.TemporaryDirectory(prefix="scrutineering-staging-") as directory:
            root = Path(directory)
            queue = ManagedEventQueue(JsonlEventStore(root / "events.jsonl"), ReplayCheckpoint(root / "offset.json"))
            queue.enqueue(RuntimeEvent(event_type="process", container_id="staging"))
            delivered = []
            async def sink(event): delivered.append(event["event_type"])
            result = await queue.drain(sink)
            assert result.delivered == 1 and delivered == ["process"]
        print("PASS shared cache and checkpointed runtime delivery")

    asyncio.run(exercise_async_boundaries())

    logger = AuditLogger()
    logger.log(AuditEvent.SCAN_COMPLETED, "staging")
    receipt = logger.anchor_head(AuditAnchor(lambda digest: f"staging-anchor:{digest[-8:]}"))
    assert receipt["anchor_id"].startswith("staging-anchor:")
    print("PASS durable audit-head anchoring boundary")

    artifact = {"image": "scrutineering-planner", "digest": "sha256:" + "b" * 64}
    envelope = build_evidence(
        artifact=artifact, artifact_type="provenance", format="slsa-provenance",
        subject_digest="sha256:" + "b" * 64, tool_name="staging-builder", tool_version="1",
        signature_provider="cosign", signature_identity="staging-release@example.test",
        signature_value="staging-signature", generated_at="2026-11-09T12:00:00Z",
    )
    assert verify_release_evidence(
        envelope, artifact,
        env={"NODE_ENV": "production", "COSIGN_CERTIFICATE_IDENTITY": "staging-release@example.test", "COSIGN_OIDC_ISSUER": "https://token.actions.githubusercontent.com"},
        verifier_factory=FakeEvidenceVerifier,
    )
    print("PASS keyless release evidence promotion boundary")

    rules = Path("monitoring/prometheus-rules.yaml").read_text()
    dashboard = json.loads(Path("monitoring/grafana-dashboard.json").read_text())
    assert "ScrutineeringScanFailureRateHigh" in rules
    assert "ScrutineeringScanLatencyP95High" in rules
    assert "ScrutineeringRuntimeEventsDeadLettered" in rules
    assert len(dashboard.get("panels", [])) >= 3
    print("PASS monitoring alerts and dashboard coverage")


if __name__ == "__main__":
    main()
