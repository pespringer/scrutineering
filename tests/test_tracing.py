from src.telemetry.tracing import span


def test_span_has_dependency_free_fallback():
    with span("scan", {"scanner": "trivy"}):
        value = True
    assert value
