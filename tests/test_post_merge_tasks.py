from types import SimpleNamespace

from src.remediation.post_merge_tasks import post_merge_scan_target, queue_post_merge_scan


def test_filesystem_publication_rescans_the_worker_checkout(monkeypatch):
    publication = SimpleNamespace(
        remediation=SimpleNamespace(
            image=SimpleNamespace(repo_name="local/source-fixture", tag="filesystem", full_name="local/source-fixture:filesystem")
        )
    )
    monkeypatch.setenv("REMEDIATION_SCAN_REPOSITORY_ROOT", "/workspace/repository")

    assert post_merge_scan_target(publication) == "fs:/workspace/repository/source-fixture"


def test_post_merge_scan_queue_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr("src.scan.tasks.enqueue_scan", lambda *args, **kwargs: calls.append((args, kwargs)))
    publication = SimpleNamespace(
        id=12,
        post_merge_scan_id=None,
        scan_status=None,
        remediation=SimpleNamespace(
            image=SimpleNamespace(repo_name="local/source-fixture", tag="filesystem", full_name="local/source-fixture:filesystem")
        ),
    )

    first = queue_post_merge_scan(None, publication)
    second = queue_post_merge_scan(None, publication)

    assert first == second == "postmerge-12"
    assert len(calls) == 1
    assert calls[0][0] == ("fs:/workspace/repository/source-fixture",)
    assert calls[0][1] == {"priority": "high", "scan_id": "postmerge-12"}
