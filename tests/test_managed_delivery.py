import asyncio
from src.runtime.managed_delivery import deliver_events


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
