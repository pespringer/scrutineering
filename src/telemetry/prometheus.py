"""Small dependency-free Prometheus exposition registry."""

from __future__ import annotations

from collections import defaultdict
from threading import Lock


class MetricsRegistry:
    def __init__(self, max_series: int = 10_000):
        if max_series < 1: raise ValueError("max_series must be positive")
        self._counters = defaultdict(float)
        self._gauges = defaultdict(float)
        self._histograms = defaultdict(list)
        self._lock = Lock()
        self.max_series = max_series

    def increment(self, name: str, value: float = 1, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            if (name, self._labels(labels)) not in self._counters and len(self._counters) >= self.max_series: raise RuntimeError("metric series limit reached")
            self._counters[(name, self._labels(labels))] += value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            if (name, self._labels(labels)) not in self._gauges and len(self._gauges) >= self.max_series: raise RuntimeError("metric series limit reached")
            self._gauges[(name, self._labels(labels))] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        if not isinstance(value, (int, float)) or value < 0: raise ValueError("metric observation must be non-negative")
        with self._lock:
            self._histograms[(name, self._labels(labels))].append(float(value))

    def clear(self) -> None:
        """Remove all metric values, primarily for isolated tests."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()

    def snapshot(self) -> dict[str, dict[str, float]]:
        """Return a lock-protected structured view for diagnostics and tests."""
        with self._lock:
            return {
                "counters": {f"{name}|{labels}": value for (name, labels), value in self._counters.items()},
                "gauges": {f"{name}|{labels}": value for (name, labels), value in self._gauges.items()},
                "histograms": {f"{name}|{labels}": list(values) for (name, labels), values in self._histograms.items()},
            }

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
            for (name, labels), values in sorted(self._histograms.items()):
                for quantile, percentile in (("0.5", 0.5), ("0.95", 0.95)):
                    ordered = sorted(values)
                    index = min(len(ordered) - 1, int(len(ordered) * percentile))
                    suffix = f"{labels},quantile=\"{quantile}\"" if labels else f"quantile=\"{quantile}\""
                    rows.append(f"{name}{{{suffix}}} {ordered[index]:g}")
                suffix = f"{{{labels}}}" if labels else ""
                rows.append(f"{name}_count{suffix} {len(values)}")
                rows.append(f"{name}_sum{suffix} {sum(values):g}")
            return "\n".join(rows) + ("\n" if rows else "")
