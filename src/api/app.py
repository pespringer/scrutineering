"""Canonical FastAPI application composition point."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
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
from redis import Redis
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

    def error_payload(request: Request, code: str, message: str, status_code: int) -> JSONResponse:
        """Return one bounded error shape while preserving dashboard compatibility."""
        request_id = getattr(request.state, "request_id", "")
        if not request_id:
            supplied = request.headers.get("x-request-id", "")
            request_id = supplied if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied) else str(uuid4())
            request.state.request_id = request_id
        return JSONResponse(
            {"error": {"code": code, "message": message, "requestId": request_id}, "detail": message},
            status_code=status_code,
            headers={"X-Request-ID": request_id} if request_id else None,
        )

    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "Request rejected"
        code = re.sub(r"[^a-z0-9]+", "_", detail.lower()).strip("_") or f"http_{exc.status_code}"
        return error_payload(request, code, detail, exc.status_code)

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return error_payload(request, "validation_error", "Request validation failed", 422)

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        return error_payload(request, "internal_error", "Internal server error", 500)

    @application.middleware("http")
    async def request_id_middleware(request, call_next):
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied) else str(uuid4())
        request.state.request_id = request_id
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
                    return error_payload(request, "invalid_service_auth_config", "Invalid service authentication configuration", 500)
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
                return error_payload(request, "unauthorized", "Authentication is required", 401)
            request.state.auth_method = "oidc_proxy" if proxy_authenticated else "service_auth" if service_authenticated else "api_key"
            request.state.principal_id = request.headers.get("x-authenticated-sub", "dashboard-service") if proxy_authenticated else "dashboard-service"
            request.state.principal_email = request.headers.get("x-authenticated-email") if proxy_authenticated else None
            default_roles = [role.strip() for role in os.environ.get("DASHBOARD_DEFAULT_ROLES", "dashboard,operator").split(",") if role.strip()]
            request.state.principal_roles = [role.strip() for role in request.headers.get("x-authenticated-roles", "").split(",") if role.strip()] if proxy_authenticated else default_roles
            request.state.principal_tenant_ids = [tenant.strip() for tenant in request.headers.get("x-authenticated-tenant-ids", "").split(",") if tenant.strip()] if proxy_authenticated else []
            try:
                rate_limit = max(0, int(os.environ.get("API_RATE_LIMIT_PER_MINUTE", "600")))
            except ValueError:
                return error_payload(request, "invalid_rate_limit_config", "Invalid API rate-limit configuration", 500)
            if rate_limit:
                try:
                    redis_client = Redis.from_url(os.environ.get("CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0")), socket_connect_timeout=1, socket_timeout=1)
                    bucket = int(time.time() // 60)
                    rate_key = f"scrutineering:api-rate:{request.state.principal_id}:{bucket}"
                    current = int(redis_client.incr(rate_key))
                    if current == 1:
                        redis_client.expire(rate_key, 60)
                    remaining = max(0, rate_limit - current)
                    redis_client.close()
                    request.state.rate_limit = (rate_limit, remaining)
                    if current > rate_limit:
                        response = error_payload(request, "rate_limited", "Too many requests; retry later", 429)
                        response.headers["Retry-After"] = "60"
                        response.headers["X-RateLimit-Limit"] = str(rate_limit)
                        response.headers["X-RateLimit-Remaining"] = "0"
                        return response
                except Exception:
                    # Queue availability must not become an API outage.
                    request.state.rate_limit = (rate_limit, None)
        if provider_webhook:
            request.state.auth_method = "provider_hmac"
            request.state.principal_id = f"provider:{request.url.path.rsplit('/', 1)[-1]}"
            request.state.principal_roles = []
        response = await call_next(request)
        if hasattr(request.state, "rate_limit"):
            limit, remaining = request.state.rate_limit
            response.headers["X-RateLimit-Limit"] = str(limit)
            if remaining is not None:
                response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

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
