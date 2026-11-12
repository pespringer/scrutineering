"""Convert a JSON array of audit records to canonical JSONL."""
import argparse, json
from src.remediation.audit_export import iter_jsonl

parser = argparse.ArgumentParser()
parser.add_argument("input")
args = parser.parse_args()
records = json.load(open(args.input, encoding="utf-8"))
for line in iter_jsonl(records): print(line, end="")
