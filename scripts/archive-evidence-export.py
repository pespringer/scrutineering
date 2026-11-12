"""Create or verify a portable evidence archive from JSON records."""
import argparse, json
from src.remediation.evidence_archive import manifest, verify_manifest

parser = argparse.ArgumentParser()
parser.add_argument("input")
parser.add_argument("--verify", action="store_true")
args = parser.parse_args()
value = json.load(open(args.input, encoding="utf-8"))
if args.verify:
    if not verify_manifest(value): raise SystemExit("evidence archive verification failed")
    print("PASS evidence archive")
else:
    records = value.get("records", value if isinstance(value, list) else [value])
    print(json.dumps(manifest(records), indent=2, sort_keys=True))
