from __future__ import annotations

from dataclasses import dataclass
import inspect
import asyncio

from .replay_checkpoint import ReplayCheckpoint
from src.telemetry.scan_metrics import record_runtime_delivery


@dataclass
class DeliveryResult:
    delivered: int
    dead_lettered: int


class ManagedEventQueue:
    """Checkpointed queue facade over the durable event store and a managed sink."""

    def __init__(self, store, checkpoint: ReplayCheckpoint, *, max_batch: int = 1000):
        if max_batch < 1: raise ValueError("max_batch must be positive")
        self.store = store
        self.checkpoint = checkpoint
        self.max_batch = max_batch

    def enqueue(self, event) -> None:
        self.store.append(event)

    async def drain(self, sink, *, max_attempts: int = 3, retry_delay_seconds: float = 0, dead_letter=None) -> DeliveryResult:
        offset = self.checkpoint.load()
        next_offset, events = self.store.read_from(offset, self.max_batch)
        if not events:
            self.checkpoint.save(next_offset)
            return DeliveryResult(0, 0)
        result = await deliver_events(
            events, sink, max_attempts=max_attempts, max_batch=self.max_batch,
            retry_delay_seconds=retry_delay_seconds, dead_letter=dead_letter,
        )
        record_runtime_delivery(result.delivered, result.dead_lettered)
        if result.delivered + result.dead_lettered == len(events):
            self.checkpoint.save(next_offset)
        return result


async def deliver_events(events, sink, *, max_attempts: int = 3, max_batch: int = 1000, retry_delay_seconds: float = 0, dead_letter=None) -> DeliveryResult:
    if max_attempts < 1: raise ValueError("max_attempts must be positive")
    if max_batch < 1: raise ValueError("max_batch must be positive")
    if retry_delay_seconds < 0: raise ValueError("retry_delay_seconds must be non-negative")
    events = list(events)
    if len(events) > max_batch: raise ValueError("event batch exceeds limit")
    delivered = dead_lettered = 0
    for event in events:
        sent = False
        for _ in range(max_attempts):
            try:
                await sink(event); sent = True; delivered += 1; break
            except Exception:
                if retry_delay_seconds: await asyncio.sleep(retry_delay_seconds)
                continue
        if not sent:
            dead_lettered += 1
            if dead_letter:
                result = dead_letter(event)
                if inspect.isawaitable(result): await result
    return DeliveryResult(delivered, dead_lettered)
