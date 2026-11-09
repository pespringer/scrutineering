import pytest
from src.telemetry.otel_config import load_otel_config


def test_otel_config_validates_endpoint():
    config = load_otel_config({"OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.test", "OTEL_SERVICE_NAME": "scanner", "OTEL_EXPORTER_OTLP_HEADERS": "authorization=secret"})
    assert config["enabled"] and config["headers"]["authorization"] == "secret"
    with pytest.raises(ValueError): load_otel_config({"OTEL_EXPORTER_OTLP_ENDPOINT": "file:///tmp/otel"})
