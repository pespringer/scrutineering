"""Evaluate a receiver-independent production promotion gate."""

import argparse
import json

from src.platform.promotion_gate import production_promotion_gate

parser = argparse.ArgumentParser()
parser.add_argument("checks", help="JSON object containing promotion check booleans")
args = parser.parse_args()
with open(args.checks, encoding="utf-8") as handle:
    checks = json.load(handle)
result = production_promotion_gate(**{key: bool(checks.get(key, False)) for key in ("tests_passed", "migrations_valid", "deployment_valid", "backup_fresh", "recovery_ready", "configuration_clean")})
print(json.dumps(result, sort_keys=True))
if result["status"] != "ready":
    raise SystemExit(1)
