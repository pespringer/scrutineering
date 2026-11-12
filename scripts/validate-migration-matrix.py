"""Validate the checked-in Alembic chain has one linear head and no gaps."""
from pathlib import Path
import re

files = sorted(Path("src/db/migrations/versions").glob("*.py"))
revisions = {}
parents = {}
for path in files:
    text = path.read_text()
    revision = re.search(r'^revision(?:\s*:\s*[^=]+)?\s*=\s*[\'\"]([^\'\"]+)[\'\"]', text, re.M)
    parent = re.search(r'^down_revision(?:\s*:\s*[^=]+)?\s*=\s*[\'\"]([^\'\"]+)[\'\"]', text, re.M)
    if revision:
        revisions[revision.group(1)] = path.name
        parents[revision.group(1)] = parent.group(1) if parent else None
children = {parent for parent in parents.values() if parent}
heads = set(revisions) - children
assert len(heads) == 1, f"expected one migration head, found {heads}"
seen = set()
current = next(iter(heads))
while current:
    assert current not in seen, "migration cycle detected"
    seen.add(current)
    current = parents[current]
assert seen == set(revisions), "migration chain contains an unreachable revision"
print(f"PASS migration chain ({len(revisions)} revisions, head {next(iter(heads))})")
