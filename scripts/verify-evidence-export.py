"""Verify a JSON evidence envelope produced by sign-evidence-export.py."""
import argparse, json, sys
from src.remediation.evidence_export import verify_export

parser = argparse.ArgumentParser()
parser.add_argument("envelope")
parser.add_argument("--secret", required=True)
args = parser.parse_args()
envelope = json.load(open(args.envelope, encoding="utf-8"))
if not verify_export(envelope["payload"], envelope["signature"], args.secret):
    raise SystemExit("evidence signature verification failed")
print("PASS evidence signature")
