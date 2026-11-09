from pathlib import Path


def test_audit_chain_migration_declares_hash_columns():
    migration = Path("src/db/migrations/versions/20261109_02_add_audit_chain_hashes.py").read_text()
    assert 'add_column("audit_log"' in migration
    assert '"record_hash"' in migration
