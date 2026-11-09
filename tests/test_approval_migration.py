from pathlib import Path


def test_approval_migration_is_chained():
    migration = Path("src/db/migrations/versions/20261109_03_add_remediation_approval.py").read_text()
    assert 'down_revision = "20261109_02"' in migration
    assert '"approval_token_hash"' in migration
