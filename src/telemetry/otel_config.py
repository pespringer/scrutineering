from __future__ import annotations

from urllib.parse import urlparse


def parse_headers(value: str) -> dict[str, str]:
    result = {}
    for item in value.split(",") if value else []:
        if "=" not in item: raise ValueError("OTLP headers must use key=value")
        key, header_value = item.split("=", 1)
        if not key.strip(): raise ValueError("OTLP header key is required")
        result[key.strip()] = header_value.strip()
    return result


def load_otel_config(env: dict[str, str] | None = None) -> dict[str, object]:
    values = env or {}
    endpoint = str(values.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")).strip()
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must be an HTTP(S) URL")
    headers = str(values.get("OTEL_EXPORTER_OTLP_HEADERS", "")).strip()
    return {"endpoint": endpoint or None, "service_name": values.get("OTEL_SERVICE_NAME", "scrutineering"), "headers": parse_headers(headers), "enabled": bool(endpoint)}
