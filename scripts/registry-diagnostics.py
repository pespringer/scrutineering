"""Report private registry configuration without printing credentials."""

import argparse
import json
import os

from src.scan.registry_diagnostics import diagnose_registry

parser = argparse.ArgumentParser()
parser.add_argument("registry")
args = parser.parse_args()
result = diagnose_registry(args.registry, dict(os.environ))
print(json.dumps({"registry": result.registry, "configured": result.configured, "required_keys": result.required_keys, "missing_keys": result.missing_keys, "message": result.message}, sort_keys=True))
