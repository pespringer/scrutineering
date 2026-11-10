from src.runtime.managed_delivery import ManagedEventQueue
from src.runtime.event_store import JsonlEventStore
from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.replay_checkpoint import ReplayCheckpoint
from src.telemetry.scan_metrics import scan_metrics


def test_managed_delivery_records_dead_letter_metric(tmp_path):
    queue = ManagedEventQueue(JsonlEventStore(tmp_path / "events.jsonl"), ReplayCheckpoint(tmp_path / "offset.json"))
    queue.enqueue(RuntimeEvent(event_type="process", container_id="c1"))

    async def sink(event):
        raise RuntimeError("down")

    import asyncio
    scan_metrics.clear()
    asyncio.run(queue.drain(sink, max_attempts=1))
    assert "scrutineering_runtime_events_dead_lettered_total|" in scan_metrics.snapshot()["counters"]
