#!/usr/bin/env python3
"""Live golden path against the running Compose stack (make up), with real scanners.

Builds fixtures/images/vulnerable-node, pushes it to the local registry, scans it
through the dashboard API, and checks the targeted finding. The remediation half
(propose -> approve -> build -> rescan -> resolved) is reported as pending until
Phase 4 of docs/RESET-PLAN.md implements it.

Environment: E2E_DASHBOARD_URL (default http://localhost:3001),
E2E_PUSH_HOST (localhost:5000), E2E_SCAN_HOST (registry:5000), E2E_TIMEOUT_SECONDS (900).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = os.environ.get("E2E_DASHBOARD_URL", "http://localhost:3001").rstrip("/")
PUSH_HOST = os.environ.get("E2E_PUSH_HOST", "localhost:5000")
SCAN_HOST = os.environ.get("E2E_SCAN_HOST", "registry:5000")
TIMEOUT = int(os.environ.get("E2E_TIMEOUT_SECONDS", "900"))
REPO = "fixtures/vulnerable-node:e2e"
TARGET_CVE, TARGET_PACKAGE, FIXED = "CVE-2021-23337", "lodash", "4.17.21"


def step(message: str) -> None:
    print(f"==> {message}", flush=True)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def request(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{DASHBOARD}{path}", data=data, method=method,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        fail(f"{method} {path} returned {error.code}: {error.read().decode()[:300]}")
    raise AssertionError("unreachable")


def main() -> None:
    step(f"build and push {PUSH_HOST}/{REPO}")
    subprocess.run(["docker", "build", "-q", "-t", f"{PUSH_HOST}/{REPO}", str(ROOT / "fixtures/images/vulnerable-node")],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "push", "-q", f"{PUSH_HOST}/{REPO}"], check=True, stdout=subprocess.DEVNULL)

    image = f"{SCAN_HOST}/{REPO}"
    step(f"scan {image} through the dashboard")
    scan_id = request("POST", "/api/scans", {"image_name": image, "priority": "high"})["scan_id"]
    deadline = time.monotonic() + TIMEOUT
    while True:
        scan = request("GET", f"/api/scans/{scan_id}")
        if scan["status"] in {"completed", "partial", "failed", "cancelled"}:
            break
        if time.monotonic() > deadline:
            fail(f"scan {scan_id} still {scan['status']} after {TIMEOUT}s")
        time.sleep(3)
    if scan["status"] != "completed":
        fail(f"scan ended {scan['status']}: {scan.get('error_message')}")
    print(f"    completed: {scan['findings']} findings")

    step(f"check {TARGET_CVE} in {TARGET_PACKAGE}")
    findings, offset = [], 0
    while True:
        page = request("GET", f"/api/scans/{scan_id}/findings?limit=200&offset={offset}")
        findings += page["items"]
        offset += page["count"]
        if offset >= page["total"] or not page["count"]:
            break
    target = [f for f in findings if f["cve_id"] == TARGET_CVE and f["package_name"] == TARGET_PACKAGE]
    if len(target) != 1:
        fail(f"expected one {TARGET_CVE} finding, found {len(target)}")
    if target[0]["fixed_version"] != FIXED:
        fail(f"expected fixed version {FIXED}, got {target[0]['fixed_version']}")
    print(f"    found: {TARGET_PACKAGE} {target[0]['package_version']} -> {FIXED}")

    step("remediation half: pending Phase 4 (propose, approve, build, rescan, resolve)")
    print("PASS: scan half of the golden path")


if __name__ == "__main__":
    main()
