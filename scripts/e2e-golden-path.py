#!/usr/bin/env python3
"""Live golden path against the running Compose stack (make up), with real scanners.

Scan half: build fixtures/images/vulnerable-node, push it to the local registry,
scan it through the dashboard API, and check the targeted lodash finding.

Remediation half: connect the image to a git copy of its source under
.local/remediation-sources, propose the lodash fix, approve and execute it (the
worker patches the source with npm, builds the candidate on buildkitd, runs the
source's test command inside it, and scans it), then publish the candidate as the image's tag, rescan, and expect the
remediation to complete. Needs REMEDIATION_EXECUTION_ENABLED=true.

Environment: E2E_DASHBOARD_URL (default http://localhost:3001),
E2E_PUSH_HOST (localhost:5000), E2E_SCAN_HOST (registry:5000), E2E_TIMEOUT_SECONDS (900).
"""

from __future__ import annotations

import json
import os
import shutil
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
# Runs inside the candidate image: the patched lodash is the one installed.
TEST_COMMAND = ["node", "-e", f"process.exit(require('lodash/package.json').version === '{FIXED}' ? 0 : 1)"]


def step(message: str) -> None:
    print(f"==> {message}", flush=True)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def request(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{DASHBOARD}{path}", data=data, method=method, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        fail(f"{method} {path} returned {error.code}: {error.read().decode()[:300]}")
    raise AssertionError("unreachable")


def wait_for_scan(scan_id: str) -> dict:
    deadline = time.monotonic() + TIMEOUT
    while True:
        scan = request("GET", f"/api/scans/{scan_id}")
        if scan["status"] in {"completed", "partial", "failed", "cancelled"}:
            return scan
        if time.monotonic() > deadline:
            fail(f"scan {scan_id} still {scan['status']} after {TIMEOUT}s")
        time.sleep(3)


def scan_image(image: str) -> dict:
    scan = wait_for_scan(request("POST", "/api/scans", {"image_name": image, "priority": "high"})["scan_id"])
    if scan["status"] != "completed":
        fail(f"scan ended {scan['status']}: {scan.get('error_message')}")
    return scan


def prepare_source() -> str:
    """A fresh git repository of the fixture source, where the worker mounts sources from."""
    name = "vulnerable-node-e2e"
    repository = ROOT / ".local" / "remediation-sources" / name
    shutil.rmtree(repository, ignore_errors=True)
    shutil.copytree(ROOT / "fixtures/images/vulnerable-node", repository)
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(
            ["git", "-c", "user.name=e2e", "-c", "user.email=e2e@example.invalid", *args], cwd=repository, check=True
        )
    return name


def remediation_half(scan: dict, target: dict) -> None:
    image_id = scan["image_id"]
    if target.get("remediation_id"):
        # A previous run's remediation may still hold the finding.
        previous = request("GET", f"/api/remediations/{target['remediation_id']}")
        if previous["status"] not in {"completed", "cancelled"}:
            request("POST", f"/api/remediations/{previous['id']}/cancel")

    step("connect the image to its source")
    request("PUT", f"/api/images/{image_id}/source", {"repository": prepare_source(), "test_command": TEST_COMMAND})

    step(f"propose, approve and execute the {TARGET_PACKAGE} fix")
    body = {"image_id": image_id, "finding_ids": [target["id"]]}
    preview = request("POST", "/api/remediations/preview", body)
    if preview["actionable_count"] != 1:
        fail(f"expected one actionable finding, preview: {preview}")
    remediation_id = request("POST", "/api/remediations", body)["id"]
    request("POST", f"/api/remediations/{remediation_id}/approve")
    request("POST", f"/api/remediations/{remediation_id}/execute")
    deadline = time.monotonic() + TIMEOUT
    while True:
        remediation = request("GET", f"/api/remediations/{remediation_id}")
        if remediation["status"] not in {"building", "verifying"}:
            break
        if time.monotonic() > deadline:
            fail(f"remediation {remediation_id} still {remediation['status']} after {TIMEOUT}s")
        time.sleep(5)
    if remediation["status"] != "ready":
        fail(f"remediation {remediation_id} ended {remediation['status']}: {remediation.get('error_message')}")
    verification = remediation["verification"]
    print(f"    ready: {remediation['candidate_image']}@{remediation['candidate_digest'][:19]}…")
    events = [event["event_type"] for event in request("GET", f"/api/remediations/{remediation_id}/events")["events"]]
    if "tested" not in events:
        fail(f"the test command did not run: events {events}")
    print("    the source's test command passed inside the candidate")
    print(f"    candidate has {verification['candidate_findings']} findings, none of the targeted ones")

    step("publish the candidate as the image's tag and rescan it")
    candidate = remediation["candidate_image"].replace(SCAN_HOST, PUSH_HOST, 1)
    for command in (["pull", "-q", candidate], ["tag", candidate, f"{PUSH_HOST}/{REPO}"]):
        subprocess.run(["docker", *command], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "push", "-q", f"{PUSH_HOST}/{REPO}"], check=True, stdout=subprocess.DEVNULL)
    scan_image(f"{SCAN_HOST}/{REPO}")
    remediation = request("GET", f"/api/remediations/{remediation_id}")
    if remediation["status"] != "completed" or remediation["resolved_finding_count"] != 1:
        fail(f"expected remediation {remediation_id} completed, got {remediation['status']}")
    print(f"    remediation {remediation_id} completed; {TARGET_CVE} resolved")


def notifications_check() -> None:
    """Send a test notification to each configured channel and wait for it to be delivered."""
    page = request("GET", "/api/notifications")
    configured = [channel["name"] for channel in page["channels"] if channel["configured"]]
    if not configured:
        print("    skipped: no notification channel is configured")
        return
    step(f"send a test notification to {', '.join(configured)}")
    ids = {item["id"] for item in request("POST", "/api/notifications/test")["queued"]}
    for _ in range(30):
        rows = [item for item in request("GET", "/api/notifications")["deliveries"] if item["id"] in ids]
        if rows and all(row["status"] == "sent" for row in rows):
            print(f"    delivered to {', '.join(row['channel'] for row in rows)}")
            return
        refused = [row for row in rows if row["status"] == "failed" or row["attempts"]]
        if refused:
            fail("; ".join(f"{row['channel']} refused the test: {row['last_error']}" for row in refused))
        time.sleep(1)
    fail("the test notification was not delivered within 30 seconds; does the worker consume the notify queue?")


def main() -> None:
    step(f"build and push {PUSH_HOST}/{REPO}")
    subprocess.run(
        ["docker", "build", "-q", "-t", f"{PUSH_HOST}/{REPO}", str(ROOT / "fixtures/images/vulnerable-node")],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(["docker", "push", "-q", f"{PUSH_HOST}/{REPO}"], check=True, stdout=subprocess.DEVNULL)

    image = f"{SCAN_HOST}/{REPO}"
    step(f"scan {image} through the dashboard")
    scan = scan_image(image)
    scan_id = scan["scan_id"]
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

    remediation_half(scan, target[0])
    step("check notifications")
    notifications_check()
    print("PASS: golden path (scan, fix, build, verify, rescan, complete, notify)")


if __name__ == "__main__":
    main()
