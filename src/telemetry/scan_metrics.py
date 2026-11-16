from .prometheus import MetricsRegistry

scan_metrics = MetricsRegistry()


def record_scan(status: str, scanner: str | None = None) -> None:
    labels = {"status": status}
    if scanner: labels["scanner"] = scanner
    scan_metrics.increment("scrutineering_scans_total", labels=labels)


def record_scan_latency(seconds: float, scanner: str | None = None) -> None:
    if seconds < 0: raise ValueError("scan latency must be non-negative")
    scan_metrics.observe("scrutineering_scan_latency_seconds", seconds, labels={"scanner": scanner} if scanner else None)


def record_provider_callback(outcome: str) -> None:
    if outcome not in {"accepted", "rejected", "duplicate", "unmatched", "rollback_required"}:
        raise ValueError("unknown provider callback outcome")
    scan_metrics.increment("scrutineering_provider_callbacks_total", labels={"outcome": outcome})


def set_queue_health(queue: str, depth: int, oldest_age_seconds: int) -> None:
    if not queue or depth < 0 or oldest_age_seconds < 0:
        raise ValueError("invalid queue health")
    labels = {"queue": queue}
    scan_metrics.set_gauge("scrutineering_queue_depth", depth, labels=labels)
    scan_metrics.set_gauge("scrutineering_queue_oldest_age_seconds", oldest_age_seconds, labels=labels)
