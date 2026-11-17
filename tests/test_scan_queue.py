import pytest

from src.scan.queue import scan_task_options


def test_scan_task_options_are_broker_ready():
    assert scan_task_options("high") == {"queue": "scan.high", "priority": 9}
    with pytest.raises(ValueError):
        scan_task_options("urgent")
