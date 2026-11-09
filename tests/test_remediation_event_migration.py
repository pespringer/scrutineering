from pathlib import Path


def test_remediation_event_migration_is_chained():
    path = Path("src/db/migrations/versions/20261109_04_add_remediation_events.py")
    text = path.read_text()
    assert 'down_revision = "20261109_03"' in text
    assert '"remediation_events"' in text
