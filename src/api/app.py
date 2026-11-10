"""Canonical FastAPI application composition point."""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from uuid import uuid4
import re

from src.analytics.api import router as analytics_router
from src.forensics.api import router as forensics_router
from src.runtime.api import router as runtime_router
from src.scan.api import router as scan_router
from src.scan.api import set_scan_data_provider
from src.scan.db_provider import SqlAlchemyScanDataProvider
from src.db.connection import get_session
from src.api.readiness import check_database
from src.telemetry.scan_metrics import scan_metrics as metrics
from src.api.auth import is_api_key_authorized
from src.api.service_auth import create_replay_guard, verify_service_request
import os
import time
from fastapi.responses import JSONResponse


def is_service_request_authorized(headers, body: bytes, secret: str, replay_guard, *, max_skew_seconds: int = 300) -> bool:
    """Verify one internal request and consume its signature replay token."""
    if not secret:
        return False
    if not verify_service_request(headers, body, secret, max_skew_seconds=max_skew_seconds):
        return False
    signature = headers.get("x-service-signature", "")
    return replay_guard(signature, int(time.time()))


def create_app() -> FastAPI:
    application = FastAPI(title="Scrutineering API", version="1.0")
    service_replay_guard = create_replay_guard()
    set_scan_data_provider(SqlAlchemyScanDataProvider(get_session))
    application.include_router(scan_router)
    application.include_router(runtime_router)
    application.include_router(analytics_router)
    application.include_router(forensics_router)

    @application.middleware("http")
    async def request_id_middleware(request, call_next):
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied) else str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @application.middleware("http")
    async def api_auth_middleware(request, call_next):
        expected = os.environ.get("PYTHON_API_KEY", "")
        public_paths = {"/health", "/ready", "/metrics", "/version"}
        if request.url.path not in public_paths:
            body = await request.body()
            service_secret = os.environ.get("SERVICE_AUTH_SECRET", "")
            service_headers = {key: value for key, value in request.headers.items() if key.startswith("x-service-")}
            service_authenticated = False
            if service_secret and service_headers:
                try:
                    max_skew = int(os.environ.get("SERVICE_AUTH_MAX_SKEW_SECONDS", "300"))
                except ValueError:
                    return JSONResponse({"error": "invalid_service_auth_config"}, status_code=500)
                service_authenticated = is_service_request_authorized(
                    service_headers, body, service_secret, service_replay_guard, max_skew_seconds=max_skew,
                )
            api_authenticated = bool(expected and is_api_key_authorized(request, expected))
            required_service_auth = os.environ.get("SERVICE_AUTH_REQUIRED", "").lower() in {"1", "true", "yes"}
            if (required_service_auth and not service_authenticated) or (not required_service_auth and not api_authenticated and not service_authenticated):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/version", tags=["health"])
    def version() -> dict[str, str]:
        revision = os.environ.get("SCRUTINEERING_REVISION", "unknown")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", revision): revision = "unknown"
        return {"service": "scrutineering", "version": os.environ.get("SCRUTINEERING_VERSION", "1.0"), "revision": revision}

    @application.get("/ready", tags=["health"])
    def readiness():
        return check_database(get_session)

    @application.get("/metrics", tags=["health"], response_class=PlainTextResponse)
    def prometheus_metrics():
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    return application


app = create_app()
