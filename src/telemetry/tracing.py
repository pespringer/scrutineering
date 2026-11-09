"""Optional OpenTelemetry bridge with a dependency-free fallback."""

from __future__ import annotations

from contextlib import contextmanager


@contextmanager
def span(name: str, attributes: dict[str, object] | None = None):
    """Yield a trace context without making OTel a runtime hard dependency."""
    if not name:
        raise ValueError("span name is required")
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer("scrutineering")
        with tracer.start_as_current_span(name, attributes=attributes or {}) as current_span:
            try:
                yield
            except Exception as exc:
                current_span.record_exception(exc)
                raise
    except ImportError:
        yield
