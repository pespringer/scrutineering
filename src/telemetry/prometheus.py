"""Small dependency-free Prometheus exposition registry."""

from __future__ import annotations

from collections import defaultdict
from threading import Lock


class MetricsRegistry:
    def __init__(self):
        self._counters = defaultdict(float)
        self._gauges = defaultdict(float)
        self._lock = Lock()

    def increment(self, name: str, value: float = 1, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            self._counters[(name, self._labels(labels))] += value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            self._gauges[(name, self._labels(labels))] = value

    @staticmethod
    def _labels(labels: dict[str, str] | None) -> str:
        if not labels: return ""
        return ",".join(f'{key}="{str(value).replace(chr(92), chr(92)+chr(92)).replace(chr(34), chr(92)+chr(34))}"' for key, value in sorted(labels.items()))

    def render(self) -> str:
        with self._lock:
            rows = []
            for (name, labels), value in sorted(self._counters.items()):
                rows.append(f"{name}{('{'+labels+'}') if labels else ''} {value:g}")
            for (name, labels), value in sorted(self._gauges.items()):
                rows.append(f"{name}{('{'+labels+'}') if labels else ''} {value:g}")
            return "\n".join(rows) + ("\n" if rows else "")
