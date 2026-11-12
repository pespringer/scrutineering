"""Create or verify a deterministic backup manifest from a JSON record export."""

import argparse
import json
from pathlib import Path

from src.remediation.backup import verify_restore_preflight, write_backup_manifest

parser = argparse.ArgumentParser()
parser.add_argument("records")
parser.add_argument("manifest")
parser.add_argument("--verify", action="store_true")
args = parser.parse_args()
records = json.loads(Path(args.records).read_text(encoding="utf-8"))
records = records if isinstance(records, list) else records.get("records", [])
if args.verify:
    value = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if not verify_restore_preflight(records, value):
        raise SystemExit("backup manifest verification failed")
    print("PASS backup restore preflight")
else:
    print(json.dumps(write_backup_manifest(records, args.manifest), indent=2, sort_keys=True))
