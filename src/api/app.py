"""Canonical FastAPI application composition point."""

from fastapi import FastAPI

from src.analytics.api import router as analytics_router
from src.forensics.api import router as forensics_router
from src.runtime.api import router as runtime_router
from src.scan.api import router as scan_router


def create_app() -> FastAPI:
    application = FastAPI(title="Scrutineering API", version="1.0")
    application.include_router(scan_router)
    application.include_router(runtime_router)
    application.include_router(analytics_router)
    application.include_router(forensics_router)

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
