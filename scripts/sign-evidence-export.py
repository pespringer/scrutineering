"""Sign a JSON evidence payload with the configured HMAC contract."""
import argparse, json, sys
from src.remediation.evidence_export import sign_export

parser = argparse.ArgumentParser()
parser.add_argument("payload", help="JSON file, or - for stdin")
parser.add_argument("--secret", required=True)
args = parser.parse_args()
raw = sys.stdin.read() if args.payload == "-" else open(args.payload, encoding="utf-8").read()
print(json.dumps({"payload": json.loads(raw), "signature": sign_export(json.loads(raw), args.secret)}, indent=2, sort_keys=True))
