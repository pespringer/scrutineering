def test_recovery_task_is_registered_with_worker_app():
    from src.scan.tasks import app

    assert "src.remediation.recovery_tasks.poll_recovery_requests" in app.tasks
    assert "src.remediation.retention_tasks.purge_expired_evidence" in app.tasks
    assert "src.remediation.alert_tasks.deliver_alerts" in app.tasks
