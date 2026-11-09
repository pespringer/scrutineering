import pytest

from src.scan.queue import scan_priority, scan_task_options


def test_scan_priority_policy():
    assert scan_priority("critical") == "high"
    assert scan_priority("medium") == "normal"
    assert scan_priority("low") == "low"
    assert scan_priority("low", deadline=True) == "high"


def test_scan_task_options_are_broker_ready():
    assert scan_task_options("high") == {"queue": "scan.high", "priority": 9}
    with pytest.raises(ValueError):
        scan_task_options("urgent")
