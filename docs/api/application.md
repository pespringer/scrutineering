# Canonical Python API

Run the composed FastAPI application with:

```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

`src.api.app:create_app()` mounts the scan-data v1, runtime monitoring,
analytics, and forensics routers. `/health` is intentionally lightweight;
database readiness and authenticated cross-service access remain deployment
configuration work.
