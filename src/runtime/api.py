"""FastAPI dashboard endpoints for runtime monitoring.

Provides the data APIs needed by the Next.js dashboard for real-time
security posture, anomaly listings, and alert management.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/runtime", tags=["runtime-monitoring"])

# Lazy-loaded service reference — set during app startup
_service: Any = None


def _get_service():
    if _service is None:
        raise HTTPException(status_code=503, detail="Runtime monitoring not started")
    return _service


def set_monitoring_service(service) -> None:
    """Called during application startup to wire in the live service."""
    global _service
    _service = service


# -- Pydantic models -------------------------------------------------------- #

class OverviewResponse(BaseModel):
    watched_containers: int
    containers: list[str]
    alert_stats: dict[str, Any]
    anomaly_count: int


class AnomalyResponse(BaseModel):
    kind: str
    severity: str
    container_id: str
    description: str
    evidence: dict[str, Any]
    detected_at: str
    resolved: bool


class AlertResponse(BaseModel):
    id: str
    anomaly_type: str
    severity: str
    container_id: str
    image_name: str | None
    title: str
    description: str
    evidence: dict[str, Any]
    created_at: str
    acknowledged: bool
    resolved: bool


class ResourceStatsResponse(BaseModel):
    cpu: dict[str, float | int]
    memory_mb: dict[str, float | int]
    network_in_bytes: dict[str, float | int]
    network_out_bytes: dict[str, float | int]
    unique_processes: int
    common_ports: dict[str, int]
    dns_queries: dict[str, int]
    last_update: float


class AcknowledgeRequest(BaseModel):
    actor: str | None = None


class AlertActionResponse(BaseModel):
    success: bool
    alert_id: str


# -- Routes ----------------------------------------------------------------- #

@router.get("/overview", response_model=OverviewResponse)
def get_overview():
    """High-level monitoring overview for dashboard header."""
    service = _get_service()
    return service.get_overview()


@router.get("/anomalies", response_model=list[AnomalyResponse])
def get_anomalies(
    container_id: str | None = Query(None, description="Filter by container"),
    since: datetime | None = Query(None, description="Only anomalies after this time"),
    resolved: bool = Query(False, description="Include resolved anomalies"),
):
    """List detected anomalies, ordered most-recent-first."""
    service = _get_service()
    results = service.get_anomalies(
        container_id=container_id,
        since=since,
        unresolved_only=not resolved,
    )
    return results


@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts(
    container_id: str | None = Query(None),
    severity: str | None = Query(None),
    resolved: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
):
    """List alerts with optional filtering."""
    service = _get_service()
    return service.get_alerts(
        container_id=container_id,
        severity=severity,
        unresolved_only=not resolved,
        limit=limit,
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertActionResponse)
def acknowledge_alert(alert_id: str, body: AcknowledgeRequest | None = None):
    """Mark an alert as acknowledged."""
    service = _get_service()
    actor = body.actor if body else None
    success = service.alert_manager.acknowledge(alert_id, actor=actor)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertActionResponse(success=True, alert_id=alert_id)


@router.post("/alerts/{alert_id}/resolve", response_model=AlertActionResponse)
def resolve_alert(alert_id: str):
    """Mark an alert as resolved."""
    service = _get_service()
    success = service.alert_manager.resolve(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertActionResponse(success=True, alert_id=alert_id)


@router.get("/stats/{container_id}", response_model=ResourceStatsResponse)
def get_resource_stats(container_id: str):
    """Resource statistics (CPU, memory, network) for a container."""
    service = _get_service()
    stats = service.get_resource_stats(container_id)
    if not stats:
        raise HTTPException(
            status_code=404,
            detail=f"No stats available for container {container_id}",
        )
    return stats


@router.get("/containers", response_model=list[str])
def get_watched_containers():
    """List containers currently under monitoring."""
    service = _get_service()
    return service.get_watched()


@router.post("/containers/{container_id}/add")
def add_container(container_id: str):
    """Manually add a container to monitoring."""
    import asyncio
    service = _get_service()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(service.add_container(container_id))
    return {"added": container_id}


@router.delete("/containers/{container_id}")
def remove_container(container_id: str):
    """Remove a container from monitoring."""
    import asyncio
    service = _get_service()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(service.remove_container(container_id))
    return {"removed": container_id}
