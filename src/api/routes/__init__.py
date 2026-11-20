"""Dashboard API: every route under /api/dashboard, grouped by area."""

from fastapi import APIRouter

from src.api.routes import (
    audit,
    deployments,
    evidence,
    findings,
    images,
    notifications,
    posture,
    remediations,
    reports,
    sboms,
    scans,
    session,
    sources,
    system,
    webhooks,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
for module in (
    posture,
    scans,
    images,
    sources,
    findings,
    session,
    system,
    audit,
    remediations,
    evidence,
    notifications,
    sboms,
    deployments,
    reports,
    webhooks,
):
    router.include_router(module.router)

__all__ = ["router"]
