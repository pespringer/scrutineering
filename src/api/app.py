"""Canonical FastAPI application composition point."""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from uuid import uuid4
import re

from src.analytics.api import router as analytics_router
from src.analytics.dashboard_api import router as dashboard_router
from src.forensics.api import router as forensics_router
from src.runtime.api import router as runtime_router
from src.scan.api import router as scan_router
from src.scan.api import set_scan_data_provider
from src.scan.db_provider import SqlAlchemyScanDataProvider
from src.db.connection import get_session
from src.db.models import Scan
from src.api.readiness import check_database
from src.telemetry.scan_metrics import scan_metrics as metrics
from src.api.auth import is_api_key_authorized
from src.api.service_auth import create_replay_guard, verify_service_request
import os
import time
import hmac
from fastapi.responses import JSONResponse
from src.telemetry.scan_metrics import record_http_request
from src.telemetry.tracing import span


def is_service_request_authorized(headers, body: bytes, secret: str, replay_guard, *, max_skew_seconds: int = 300) -> bool:
    """Verify one internal request and consume its signature replay token."""
    if not secret:
        return False
    if not verify_service_request(headers, body, secret, max_skew_seconds=max_skew_seconds):
        return False
    signature = headers.get("x-service-signature", "")
    return replay_guard(signature, int(time.time()))


def is_provider_webhook_path(path: str) -> bool:
    """Provider callbacks authenticate with their provider HMAC, not API keys."""
    return bool(re.fullmatch(r"/api/dashboard/webhooks/(github|gitlab)", path)) or path == "/api/dashboard/deployment-evidence"


def create_app() -> FastAPI:
    application = FastAPI(title="Scrutineering API", version="1.0")
    service_replay_guard = create_replay_guard()
    set_scan_data_provider(SqlAlchemyScanDataProvider(get_session))
    application.include_router(scan_router)
    application.include_router(runtime_router)
    application.include_router(analytics_router)
    application.include_router(dashboard_router)
    application.include_router(forensics_router)

    @application.middleware("http")
    async def request_id_middleware(request, call_next):
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied) else str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @application.middleware("http")
    async def telemetry_middleware(request, call_next):
        started = time.perf_counter()
        route_name = request.url.path if len(request.url.path) <= 160 else "/unmatched"
        with span("http.request", {"http.method": request.method, "http.route": route_name}):
            try:
                response = await call_next(request)
            except Exception:
                record_http_request(request.method, route_name, 500, time.perf_counter() - started)
                raise
        resolved_route = getattr(request.scope.get("route"), "path", route_name)
        record_http_request(request.method, str(resolved_route)[:160], response.status_code, time.perf_counter() - started)
        return response

    @application.middleware("http")
    async def api_auth_middleware(request, call_next):
        expected = os.environ.get("PYTHON_API_KEY", "")
        public_paths = {"/health", "/ready", "/metrics", "/version"}
        provider_webhook = is_provider_webhook_path(request.url.path)
        if request.url.path not in public_paths and not provider_webhook:
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
            proxy_secret = os.environ.get("DASHBOARD_TRUSTED_PROXY_SECRET", "")
            proxy_authenticated = bool(
                request.url.path.startswith("/api/dashboard")
                and proxy_secret
                and hmac.compare_digest(request.headers.get("x-dashboard-proxy-secret", ""), proxy_secret)
                and request.headers.get("x-authenticated-sub", "")
            )
            required_service_auth = os.environ.get("SERVICE_AUTH_REQUIRED", "").lower() in {"1", "true", "yes"}
            dashboard_api_key_allowed = request.url.path.startswith("/api/dashboard") and api_authenticated
            if (required_service_auth and not service_authenticated and not proxy_authenticated and not dashboard_api_key_allowed) or (not required_service_auth and not api_authenticated and not service_authenticated and not proxy_authenticated):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            request.state.auth_method = "oidc_proxy" if proxy_authenticated else "service_auth" if service_authenticated else "api_key"
            request.state.principal_id = request.headers.get("x-authenticated-sub", "dashboard-service") if proxy_authenticated else "dashboard-service"
            request.state.principal_email = request.headers.get("x-authenticated-email") if proxy_authenticated else None
            default_roles = [role.strip() for role in os.environ.get("DASHBOARD_DEFAULT_ROLES", "dashboard,operator").split(",") if role.strip()]
            request.state.principal_roles = [role.strip() for role in request.headers.get("x-authenticated-roles", "").split(",") if role.strip()] if proxy_authenticated else default_roles
        if provider_webhook:
            request.state.auth_method = "provider_hmac"
            request.state.principal_id = f"provider:{request.url.path.rsplit('/', 1)[-1]}"
            request.state.principal_roles = []
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
        rendered = metrics.render()
        try:
            with get_session() as session:
                for status in ("pending", "running", "completed", "failed", "cancelled", "partial"):
                    count = session.query(Scan).filter(Scan.status == status).count()
                    rendered += f'scrutineering_persisted_scans{{status="{status}"}} {count}\n'
        except Exception:
            rendered += "scrutineering_persisted_scans_unavailable 1\n"
        return PlainTextResponse(rendered, media_type="text/plain; version=0.0.4")

    return application


app = create_app()
