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


def record_provider_callback(outcome: str) -> None:
    if outcome not in {"accepted", "rejected", "duplicate", "unmatched", "rollback_required"}:
        raise ValueError("unknown provider callback outcome")
    scan_metrics.increment("scrutineering_provider_callbacks_total", labels={"outcome": outcome})


def set_stale_publications(count: int) -> None:
    if count < 0:
        raise ValueError("stale publication count must be non-negative")
    scan_metrics.set_gauge("scrutineering_stale_publications", count)


def record_reconciliation_run(status: str) -> None:
    if status not in {"completed", "failed"}:
        raise ValueError("unknown reconciliation run status")
    scan_metrics.increment("scrutineering_reconciliation_runs_total", labels={"status": status})


def record_recovery_escalation() -> None:
    scan_metrics.increment("scrutineering_recovery_escalations_total")
