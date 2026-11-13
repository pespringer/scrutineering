"""Print a dry-run scan retention report from a JSON export."""

import argparse
import json
from pathlib import Path

from src.scan.retention import ScanRetentionPolicy, cleanup_plan

parser = argparse.ArgumentParser()
parser.add_argument("records")
parser.add_argument("--days", type=int, default=90)
args = parser.parse_args()
records = json.loads(Path(args.records).read_text(encoding="utf-8"))
records = records if isinstance(records, list) else records.get("records", [])
print(json.dumps(cleanup_plan(records, ScanRetentionPolicy(days=args.days)), indent=2, sort_keys=True))
