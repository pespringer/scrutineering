"""Evaluate a receiver-independent release health check JSON file."""

import argparse
import json

from src.platform.release_health import HealthCheck, evaluate_release_health

parser = argparse.ArgumentParser()
parser.add_argument("checks", help="JSON file containing [{name, passed, detail, required}]")
args = parser.parse_args()
with open(args.checks, encoding="utf-8") as handle:
    raw = json.load(handle)
checks = [HealthCheck(name=item["name"], passed=bool(item["passed"]), detail=str(item.get("detail", "")), required=bool(item.get("required", True))) for item in raw]
print(json.dumps(evaluate_release_health(checks), sort_keys=True))
