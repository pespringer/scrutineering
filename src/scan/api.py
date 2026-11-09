"""Versioned read API for scan, finding, alert, and audit data."""

from __future__ import annotations

from typing import Any, Protocol

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


class ScanDataProvider(Protocol):
    def get_scan(self, scan_id: str) -> dict[str, Any] | None: ...
    def list_findings(self, **filters: Any) -> list[dict[str, Any]]: ...
    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]: ...
    def list_audit(self, **filters: Any) -> list[dict[str, Any]]: ...


class Page(BaseModel):
    items: list[dict[str, Any]]
    limit: int
    offset: int
    count: int
    total: int


router = APIRouter(prefix="/api/v1", tags=["scan-control-plane"])
_provider: ScanDataProvider | None = None


def set_scan_data_provider(provider: ScanDataProvider) -> None:
    global _provider
    _provider = provider


def _get_provider() -> ScanDataProvider:
    if _provider is None:
        raise HTTPException(status_code=503, detail="Scan data service not started")
    return _provider


def _page(items: list[dict[str, Any]], limit: int, offset: int) -> Page:
    window = items[offset:offset + limit]
    return Page(items=window, limit=limit, offset=offset, count=len(window), total=len(items))


def _normalized_filter(value: str | None) -> str | None:
    normalized = value.strip().lower() if value and value.strip() else None
    if normalized and len(normalized) > 512: raise HTTPException(status_code=400, detail="filter is too long")
    return normalized


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    result = _get_provider().get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/findings", response_model=Page)
def list_findings(
    severity: str | None = Query(None),
    image_digest: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page:
    items = _get_provider().list_findings(severity=_normalized_filter(severity), image_digest=_normalized_filter(image_digest))
    return _page(items, limit, offset)


@router.get("/alerts", response_model=Page)
def list_alerts(
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page:
    return _page(_get_provider().list_alerts(status=_normalized_filter(status)), limit, offset)


@router.get("/audit", response_model=Page)
def list_audit(
    actor: str | None = Query(None),
    event_type: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page:
    return _page(_get_provider().list_audit(actor=_normalized_filter(actor), event_type=_normalized_filter(event_type)), limit, offset)
