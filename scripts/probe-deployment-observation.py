#!/usr/bin/env python3
"""Run a read-only deployment observation preflight without touching the DB."""

from __future__ import annotations

import argparse
import json
import os
import sys

from src.remediation.deployment_collectors import DeploymentCollectorError, collect_observation, observation_payload
from src.remediation.deployment_config import configured_deployment_target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="Configured repository key, such as acme/api")
    parser.add_argument("--targets-json", default=None, help="Override DEPLOYMENT_COLLECTOR_TARGETS_JSON")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("DEPLOYMENT_COLLECTOR_TIMEOUT_SECONDS", "20")))
    args = parser.parse_args()
    try:
        target = configured_deployment_target(args.repository, args.targets_json)
        observation = collect_observation(target, timeout_seconds=args.timeout)
    except (DeploymentCollectorError, ValueError) as exc:
        print(json.dumps({"status": "error", "repository": args.repository, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "ready", "repository": args.repository, "observation": observation_payload(observation)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
