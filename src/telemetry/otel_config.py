from __future__ import annotations

from urllib.parse import urlparse


def load_otel_config(env: dict[str, str] | None = None) -> dict[str, object]:
    values = env or {}
    endpoint = str(values.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")).strip()
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must be an HTTP(S) URL")
    headers = str(values.get("OTEL_EXPORTER_OTLP_HEADERS", "")).strip()
    return {"endpoint": endpoint or None, "service_name": values.get("OTEL_SERVICE_NAME", "scrutineering"), "headers": headers, "enabled": bool(endpoint)}
