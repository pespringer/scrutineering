from .prometheus import MetricsRegistry

scan_metrics = MetricsRegistry()


def record_scan(status: str, scanner: str | None = None) -> None:
    labels = {"status": status}
    if scanner: labels["scanner"] = scanner
    scan_metrics.increment("scrutineering_scans_total", labels=labels)


def record_scan_latency(seconds: float, scanner: str | None = None) -> None:
    if seconds < 0: raise ValueError("scan latency must be non-negative")
    scan_metrics.observe("scrutineering_scan_latency_seconds", seconds, labels={"scanner": scanner} if scanner else None)
