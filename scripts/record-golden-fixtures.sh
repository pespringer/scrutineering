#!/usr/bin/env bash
# Rebuild the golden-path fixture images and re-record their scanner output.
#
# Requires the running Compose stack (make up). Builds images from
# fixtures/images/vulnerable-node:
#   before   - the fixture as committed (node:18.12-alpine, lodash 4.17.20)
#   patched  - what the lodash remediation produces: same base, lodash 4.17.21
#   after    - a newer base as well (node:18.20.8-alpine, lodash 4.17.21)
# pushes them to the local registry, scans them with the worker's Trivy and
# Grype, and writes trimmed JSON to fixtures/scanner-output/vulnerable-node/.
#
# Usage: scripts/record-golden-fixtures.sh [stage ...]   (default: all stages)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/fixtures/images/vulnerable-node"
out="$root/fixtures/scanner-output/vulnerable-node"
push_host="${LOCAL_REGISTRY_PUBLIC_HOST:-localhost:5000}"
scan_host="${LOCAL_REGISTRY_HOST:-registry:5000}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

stages=("${@:-before patched after}")
read -r -a stages <<< "${stages[*]}"

build_stage() {
  local stage="$1" dir="$work/$1"
  cp -r "$src/." "$dir/"
  if [ "$stage" != before ]; then
    # The same command the remediation worker runs for a direct npm dependency.
    (cd "$dir" && npm install lodash@4.17.21 --save --save-exact --package-lock-only --ignore-scripts \
      --no-audit --no-fund >/dev/null)
  fi
  if [ "$stage" = after ]; then
    sed -i 's#^FROM node:18.12-alpine#FROM node:18.20.8-alpine#' "$dir/Dockerfile"
  fi
  docker build -q -t "$push_host/fixtures/vulnerable-node:$stage" "$dir" >/dev/null
}

for stage in "${stages[@]}"; do
  case "$stage" in before|patched|after) ;; *) echo "unknown stage: $stage" >&2; exit 2 ;; esac
  mkdir -p "$work/$stage"
  build_stage "$stage"
  docker push -q "$push_host/fixtures/vulnerable-node:$stage" >/dev/null
  ref="$scan_host/fixtures/vulnerable-node:$stage"
  docker compose -f "$root/docker-compose.yml" exec -T celery-worker \
    trivy image --quiet --insecure --format json --scanners vuln \
    --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN "$ref" > "$work/$stage-trivy.raw.json"
  docker compose -f "$root/docker-compose.yml" exec -T \
    -e GRYPE_REGISTRY_INSECURE_USE_HTTP=true celery-worker \
    grype -q -o json "registry:$ref" > "$work/$stage-grype.raw.json"
  python3 "$root/scripts/trim-scanner-output.py" trivy "$work/$stage-trivy.raw.json" > "$out/$stage-trivy.json"
  python3 "$root/scripts/trim-scanner-output.py" grype "$work/$stage-grype.raw.json" > "$out/$stage-grype.json"
  echo "recorded $stage: $(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', [])))" "$out/$stage-trivy.json") trivy, $(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['matches']))" "$out/$stage-grype.json") grype"
done
