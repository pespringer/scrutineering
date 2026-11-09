from __future__ import annotations

from dataclasses import dataclass
import inspect


@dataclass
class DeliveryResult:
    delivered: int
    dead_lettered: int


async def deliver_events(events, sink, *, max_attempts: int = 3, max_batch: int = 1000, dead_letter=None) -> DeliveryResult:
    if max_attempts < 1: raise ValueError("max_attempts must be positive")
    if max_batch < 1: raise ValueError("max_batch must be positive")
    events = list(events)
    if len(events) > max_batch: raise ValueError("event batch exceeds limit")
    delivered = dead_lettered = 0
    for event in events:
        sent = False
        for _ in range(max_attempts):
            try:
                await sink(event); sent = True; delivered += 1; break
            except Exception:
                continue
        if not sent:
            dead_lettered += 1
            if dead_letter:
                result = dead_letter(event)
                if inspect.isawaitable(result): await result
    return DeliveryResult(delivered, dead_lettered)
