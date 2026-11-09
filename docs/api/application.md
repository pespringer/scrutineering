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

The scan-data router is wired to `SqlAlchemyScanDataProvider` during app
creation. It uses the repository session factory and fails closed when the
database URL is not configured.
