"""Tenant quotas, autoscaling recommendations, and queue recovery controls."""

from __future__ import annotations


def tenant_queue_quota(tenant: str, queued: int, limit: int) -> dict[str, object]:
    if not tenant or queued < 0 or limit < 1:
        raise ValueError("invalid tenant queue quota")
    return {"tenant": tenant, "queued": queued, "limit": limit, "admit": queued < limit, "remaining": max(0, limit - queued)}


def autoscale_recommendation(*, queue_depth: int, workers: int, target_per_worker: int = 10) -> dict[str, int | str]:
    if min(queue_depth, workers) < 0 or target_per_worker < 1:
        raise ValueError("invalid autoscale inputs")
    desired = max(1, (queue_depth + target_per_worker - 1) // target_per_worker)
    return {"current_workers": workers, "desired_workers": desired, "action": "scale_up" if desired > workers else "scale_down" if desired < workers else "hold"}


def queue_recovery(*, depth: int, oldest_age_seconds: int, threshold_seconds: int = 900) -> dict[str, object]:
    if min(depth, oldest_age_seconds) < 0 or threshold_seconds < 1:
        raise ValueError("invalid queue recovery inputs")
    starved = depth > 0 and oldest_age_seconds >= threshold_seconds
    return {"starved": starved, "action": "requeue_or_scale" if starved else "observe", "depth": depth, "oldest_age_seconds": oldest_age_seconds}
