from unittest.mock import Mock

from src.scan.scheduled import schedule_active_scans


class Image:
    def __init__(self, name): self.full_name = name


class Query:
    def filter(self, *_): return self
    def order_by(self, *_): return self
    def all(self): return [Image("alpine:3.20"), Image("nginx:1.27")]


class Session:
    def query(self, *_): return Query()
    def __enter__(self): return self
    def __exit__(self, *_): return False


def test_schedule_active_scans_queues_bounded_inventory(monkeypatch):
    monkeypatch.setattr("src.scan.scheduled.get_session", lambda: Session())
    enqueue = Mock()
    result = schedule_active_scans(enqueue, limit=1)
    assert result == {"discovered": 1, "queued": 1, "suppressed": 0}
    enqueue.assert_called_once_with("alpine:3.20", priority="low")
