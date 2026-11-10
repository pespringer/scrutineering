from pathlib import Path
import re


def test_release_control_migrations_are_contiguous():
    versions = Path("src/db/migrations/versions")
    by_revision = {}
    for path in sorted(versions.glob("*.py")):
        text = path.read_text()
        revision = re.search(r'^revision\s*=\s*"([^"]+)"', text, re.MULTILINE)
        down_revision = re.search(r'^down_revision\s*=\s*(.+)$', text, re.MULTILINE)
        if revision:
            by_revision[revision.group(1)] = down_revision.group(1).strip()
    assert by_revision["20261109_05"] == '"20261109_04"'
    assert "audit_chain_anchors" in (versions / "20261109_05_add_audit_chain_anchors.py").read_text()
