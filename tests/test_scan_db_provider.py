from datetime import datetime

from src.scan.db_provider import SqlAlchemyScanDataProvider


class FakeSession:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def execute(self, query):
        class Result:
            def __init__(self, rows): self.rows = rows
            def scalar_one_or_none(self): return self.rows[0] if self.rows else None
            def scalars(self): return self
            def all(self): return self.rows
        return Result(self.rows)


class FakeImage:
    full_name = "ghcr.io/acme/api@sha256:" + "a" * 64
    digest = "sha256:" + "a" * 64


class FakeScan:
    scan_id = "scan-1"
    status = type("Status", (), {"value": "completed"})()
    image = FakeImage()
    image_digest = None
    started_at = datetime(2026, 11, 8)
    completed_at = None
    total_findings = 2


def test_sqlalchemy_provider_serializes_immutable_scan_identity():
    provider = SqlAlchemyScanDataProvider(lambda: FakeSession([FakeScan()]))
    result = provider.get_scan("scan-1")
    assert result["image_digest"] == "sha256:" + "a" * 64
    assert result["status"] == "completed"
