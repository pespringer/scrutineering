import pytest

from src.scan.queue import load_queue_config


def test_queue_config_requires_all_priority_queues():
    config = load_queue_config({"CELERY_QUEUES": "scan.high,scan.normal,scan.low"})
    assert config["queues"] == ("scan.high", "scan.low", "scan.normal")


def test_queue_config_rejects_missing_priority_queue():
    with pytest.raises(ValueError, match="missing required"):
        load_queue_config({"CELERY_QUEUES": "scan.normal"})
