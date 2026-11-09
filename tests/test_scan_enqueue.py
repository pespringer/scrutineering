from src.scan.tasks import enqueue_scan


def test_enqueue_scan_passes_priority_to_celery(monkeypatch):
    captured = {}
    monkeypatch.setattr("src.scan.tasks.run_scan", type("Task", (), {
        "apply_async": staticmethod(lambda *args, **kwargs: captured.update(args=args, kwargs=kwargs) or "task-id")
    })())
    assert enqueue_scan("alpine:latest", priority="high", scan_id="scan-1") == "task-id"
    assert captured["kwargs"]["queue"] == "scan.high"
    assert captured["kwargs"]["priority"] == 9
