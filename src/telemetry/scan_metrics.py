from .prometheus import MetricsRegistry

scan_metrics = MetricsRegistry()


def record_scan(status: str, scanner: str | None = None) -> None:
    labels = {"status": status}
    if scanner: labels["scanner"] = scanner
    scan_metrics.increment("scrutineering_scans_total", labels=labels)


def record_scan_latency(seconds: float, scanner: str | None = None) -> None:
    if seconds < 0: raise ValueError("scan latency must be non-negative")
    scan_metrics.observe("scrutineering_scan_latency_seconds", seconds, labels={"scanner": scanner} if scanner else None)


def record_runtime_delivery(delivered: int, dead_lettered: int) -> None:
    if delivered < 0 or dead_lettered < 0:
        raise ValueError("runtime delivery counts must be non-negative")
    if delivered:
        scan_metrics.increment("scrutineering_runtime_events_delivered_total", delivered)
    if dead_lettered:
        scan_metrics.increment("scrutineering_runtime_events_dead_lettered_total", dead_lettered)
