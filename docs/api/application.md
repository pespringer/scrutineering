# Canonical Python API

Run the composed FastAPI application with:

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

`src.api.app:create_app()` mounts the scan-data v1, runtime monitoring,
analytics, and forensics routers. `/health` is intentionally lightweight;
database readiness and authenticated cross-service access remain deployment
configuration work.

All responses receive a safe `X-Request-ID`; callers may supply a matching
identifier for cross-service tracing.

Authenticated requests also receive `X-RateLimit-Limit` and
`X-RateLimit-Remaining` headers. The Redis-backed per-principal limit defaults
to 600 requests per minute and can be changed with
`API_RATE_LIMIT_PER_MINUTE`; set it to `0` only for an explicitly controlled
internal deployment. Rejected and validation errors use the bounded
`error.code`, `error.message`, and `error.requestId` envelope while retaining
`detail` for compatibility.

Set `PYTHON_API_KEY` to protect non-health API routes. Requests may use
`Authorization: Bearer ...` or `X-API-Key`; health, readiness, and metrics
remain probe-accessible.

The scan-data router is wired to `SqlAlchemyScanDataProvider` during app
creation. It uses the repository session factory and fails closed when the
database URL is not configured.
The canonical FastAPI app exposes `/health`, `/ready`, `/version`, and
`/metrics`. Readiness is dependency-aware; version includes the configured
release revision for deployment diagnostics.
