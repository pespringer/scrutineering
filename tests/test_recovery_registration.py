def test_recovery_task_is_registered_with_worker_app():
    from src.scan.tasks import app

    assert "src.remediation.recovery_tasks.poll_recovery_requests" in app.tasks
