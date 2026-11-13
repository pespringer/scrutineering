"""Print a dry-run backup rotation and freshness report from JSON metadata."""

import argparse
import json
from datetime import datetime

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, rotation_plan
from src.platform.operations import BackupRotation

parser = argparse.ArgumentParser()
parser.add_argument("records", help="JSON file containing backup artifact metadata")
parser.add_argument("--keep", type=int, default=7)
parser.add_argument("--max-age-days", type=int, default=30)
args = parser.parse_args()
records = json.loads(open(args.records, encoding="utf-8").read())
artifacts = [BackupArtifact(name=r["name"], created_at=datetime.fromisoformat(r["created_at"]), size_bytes=int(r["size_bytes"]), verified=bool(r.get("verified", False))) for r in records]
result = rotation_plan(artifacts, BackupRotation(keep=args.keep, max_age_days=args.max_age_days))
result["stale"] = [artifact.name for artifact in artifacts if not backup_fresh(artifact, max_age_days=args.max_age_days)]
print(json.dumps(result, sort_keys=True))
