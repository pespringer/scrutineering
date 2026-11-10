import asyncio
from src.runtime.managed_delivery import deliver_events
from src.runtime.managed_delivery import ManagedEventQueue
from src.runtime.event_store import JsonlEventStore
from src.runtime.ebpf_agent import RuntimeEvent
from src.runtime.replay_checkpoint import ReplayCheckpoint


def test_delivery_retries_and_dead_letters():
    attempts = {}; dead = []
    async def sink(event):
        attempts[event] = attempts.get(event, 0) + 1
        if event == "bad": raise RuntimeError("sink down")
    async def run(): return await deliver_events(["good", "bad"], sink, max_attempts=2, dead_letter=dead.append)
    result = asyncio.run(run())
    assert (result.delivered, result.dead_lettered) == (1, 1)
    assert attempts["bad"] == 2 and dead == ["bad"]


def test_delivery_rejects_oversized_batches():
    import pytest
    async def run(): return await deliver_events([1, 2], lambda _: None, max_batch=1)
    with pytest.raises(ValueError, match="batch"):
        asyncio.run(run())


def test_managed_event_queue_checkpoints_only_after_delivery(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl")
    queue = ManagedEventQueue(store, ReplayCheckpoint(tmp_path / "offset.json"), max_batch=2)
    queue.enqueue(RuntimeEvent(event_type="process", container_id="c1"))
    queue.enqueue(RuntimeEvent(event_type="network", container_id="c1"))
    delivered = []

    async def sink(event): delivered.append(event["event_type"])
    result = asyncio.run(queue.drain(sink))
    assert result.delivered == 2
    assert delivered == ["process", "network"]
    assert asyncio.run(queue.drain(sink)).delivered == 0


def test_managed_event_queue_retries_unacked_batch(tmp_path):
    store = JsonlEventStore(tmp_path / "events.jsonl")
    queue = ManagedEventQueue(store, ReplayCheckpoint(tmp_path / "offset.json"))
    queue.enqueue(RuntimeEvent(event_type="process", container_id="c1"))
    attempts = 0

    async def failing_sink(event):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("managed sink unavailable")

    async def run(): return await queue.drain(failing_sink, max_attempts=1)
    result = asyncio.run(run())
    assert result.dead_lettered == 1
    assert attempts == 1
    async def recovered_sink(event): return None
    assert asyncio.run(queue.drain(recovered_sink)).delivered == 0
