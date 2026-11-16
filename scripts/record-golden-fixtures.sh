#!/usr/bin/env bash
# Rebuild the golden-path fixture images and re-record their scanner output.
#
# Requires the running Compose stack (make up). Builds two images from
# fixtures/images/vulnerable-node:
#   before  - the fixture as committed (node:18.12-alpine, lodash 4.17.20)
#   after   - what a successful remediation produces (node:18.20.8-alpine, lodash 4.17.21)
# pushes both to the local registry, scans them with the worker's Trivy and
# Grype, and writes trimmed JSON to fixtures/scanner-output/vulnerable-node/.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/fixtures/images/vulnerable-node"
out="$root/fixtures/scanner-output/vulnerable-node"
push_host="${LOCAL_REGISTRY_PUBLIC_HOST:-localhost:5000}"
scan_host="${LOCAL_REGISTRY_HOST:-registry:5000}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

docker build -q -t "$push_host/fixtures/vulnerable-node:before" "$src" >/dev/null

cp -r "$src/." "$work/"
sed -i 's#^FROM node:18.12-alpine#FROM node:18.20.8-alpine#' "$work/Dockerfile"
(cd "$work" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund lodash@4.17.21 >/dev/null)
docker build -q -t "$push_host/fixtures/vulnerable-node:after" "$work" >/dev/null

for stage in before after; do
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
