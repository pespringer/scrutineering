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


def record_recovery_poll(outcome: str) -> None:
    if outcome not in {"acknowledged", "retrying", "failed", "rate_limited", "circuit_open"}:
        raise ValueError("unknown recovery poll outcome")
    scan_metrics.increment("scrutineering_recovery_polls_total", labels={"outcome": outcome})


def record_alert_delivery(outcome: str) -> None:
    if outcome not in {"delivered", "retrying", "dead_letter"}:
        raise ValueError("unknown alert delivery outcome")
    scan_metrics.increment("scrutineering_alert_deliveries_total", labels={"outcome": outcome})


def set_alert_queue_depth(status: str, count: int) -> None:
    if status not in {"pending", "retrying", "dead_letter", "delivered", "canceled"} or count < 0:
        raise ValueError("invalid alert queue gauge")
    scan_metrics.set_gauge("scrutineering_alert_queue_depth", count, labels={"status": status})


def record_recovery_lease(outcome: str) -> None:
    if outcome not in {"acquired", "reclaimed", "contended"}:
        raise ValueError("unknown recovery lease outcome")
    scan_metrics.increment("scrutineering_recovery_leases_total", labels={"outcome": outcome})


def set_queue_health(queue: str, depth: int, oldest_age_seconds: int) -> None:
    if not queue or depth < 0 or oldest_age_seconds < 0:
        raise ValueError("invalid queue health")
    labels = {"queue": queue}
    scan_metrics.set_gauge("scrutineering_queue_depth", depth, labels=labels)
    scan_metrics.set_gauge("scrutineering_queue_oldest_age_seconds", oldest_age_seconds, labels=labels)


def set_backup_last_success(timestamp: float) -> None:
    if timestamp < 0:
        raise ValueError("backup timestamp must not be negative")
    scan_metrics.set_gauge("scrutineering_backup_last_success_timestamp", timestamp)


def record_provider_request(provider: str, outcome: str) -> None:
    if not provider or outcome not in {"success", "permission_denied", "not_found", "rate_limited", "unavailable", "client_error"}:
        raise ValueError("invalid provider request metric")
    scan_metrics.increment("scrutineering_provider_requests_total", labels={"provider": provider, "outcome": outcome})


def record_slo(name: str, observed: float, target: float, passed: bool) -> None:
    if not name or observed < 0 or target < 0:
        raise ValueError("invalid SLO metric")
    scan_metrics.set_gauge("scrutineering_slo_observed", observed, labels={"slo": name})
    scan_metrics.set_gauge("scrutineering_slo_target", target, labels={"slo": name})
    scan_metrics.set_gauge("scrutineering_slo_pass", int(passed), labels={"slo": name})
