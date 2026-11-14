from unittest.mock import Mock
from datetime import datetime, timedelta, timezone

from src.db.models import Image as DbImage
from src.scan.reliability import ScanCooldown
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


class ScheduledImage:
    def __init__(self, image_id, name, last_scan_at=None):
        self.id = image_id
        self.full_name = name
        self.last_scan_at = last_scan_at


class ScheduledRecord:
    def __init__(self, image_id, next_run_at, enabled=True):
        self.id = image_id
        self.image_id = image_id
        self.enabled = enabled
        self.interval_seconds = 3600
        self.next_run_at = next_run_at
        self.last_queued_at = None


class ScheduledQuery:
    def __init__(self, records): self.records = records
    def filter(self, *_): return self
    def order_by(self, *_): return self
    def all(self): return self.records


class ScheduledSession:
    def __init__(self, images, schedules):
        self.images = images
        self.schedules = schedules
    def query(self, model): return ScheduledQuery(self.images if model is DbImage else self.schedules)
    def get(self, model, record_id): return next((item for item in self.schedules if item.id == record_id), None)
    def __enter__(self): return self
    def __exit__(self, *_): return False


def test_schedule_active_scans_honors_due_per_image_schedule(monkeypatch):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    scheduled = ScheduledRecord(1, now - timedelta(minutes=1))
    session = ScheduledSession([ScheduledImage(1, "alpine:3.20"), ScheduledImage(2, "nginx:1.27", now.replace(tzinfo=None))], [scheduled])
    monkeypatch.setattr("src.scan.scheduled.get_session", lambda: session)
    monkeypatch.setattr("src.scan.scheduled.set_queue_health", lambda *_: None)
    enqueue = Mock()

    result = schedule_active_scans(enqueue, cooldown=ScanCooldown(3600), now=now)

    assert result == {"discovered": 2, "queued": 1, "suppressed": 1}
    enqueue.assert_called_once_with("alpine:3.20", priority="low")
    assert scheduled.last_queued_at == now.replace(tzinfo=None)
    assert scheduled.next_run_at == now.replace(tzinfo=None) + timedelta(hours=1)
