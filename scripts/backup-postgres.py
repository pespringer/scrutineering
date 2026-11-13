"""Create a PostgreSQL logical backup with a manifest; execution is explicit."""

import argparse
import json
import os
import subprocess
from pathlib import Path

from src.remediation.backup import write_backup_manifest

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
parser.add_argument("--execute", action="store_true", help="run pg_dump; otherwise print the planned command")
args = parser.parse_args()
database_url = os.environ.get("DATABASE_URL", "")
if not database_url:
    raise SystemExit("DATABASE_URL is required")
command = ["pg_dump", "--format=custom", f"--file={args.output}", database_url]
if not args.execute:
    print(json.dumps({"dry_run": True, "command": ["pg_dump", "--format=custom", f"--file={args.output}", "<DATABASE_URL>"]}))
    raise SystemExit(0)
args.output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(command, check=True)
manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
write_backup_manifest([{"artifact": str(args.output), "size": args.output.stat().st_size}], manifest_path, source="postgres-pg_dump")
print(f"PASS postgres backup {args.output}")
