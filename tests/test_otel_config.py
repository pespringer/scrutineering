import pytest
from src.telemetry.otel_config import load_otel_config


def test_otel_config_validates_endpoint():
    assert load_otel_config({"OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.test", "OTEL_SERVICE_NAME": "scanner"})["enabled"]
    with pytest.raises(ValueError): load_otel_config({"OTEL_EXPORTER_OTLP_ENDPOINT": "file:///tmp/otel"})
