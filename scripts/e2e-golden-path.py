#!/usr/bin/env python3
"""Live golden path against the running Compose stack (make up), with real scanners.

Scan half: build fixtures/images/vulnerable-node, push it to the local registry,
scan it through the dashboard API, and check the targeted lodash finding.

Remediation half: connect the image to a git copy of its source under
.local/remediation-sources, propose the lodash fix, approve and execute it (the
worker patches the source with npm, builds the candidate on buildkitd, runs the
source's test command inside it, and scans it), then publish the candidate as the image's tag, rescan, and expect the
remediation to complete. Needs REMEDIATION_EXECUTION_ENABLED=true.

Deployments: before the fix, a container runs the fixture image (tagged locally under the name
the stack scans). After the fix completes, discovery must show it stale and the remediation
"0 of 1" on the fixed build; recreated from the new tag, "1 of 1". Skipped when discovery is off.

Then: a test notification when a channel is configured, and two runtime discovery runs in the
worker (the stack's own pulled images are found and scanned once; images built here are skipped).

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
# A container of the fixture image, for the deployment checks (docs/design/deployment-observation.md).
DEPLOYED = "e2e-deployed-vulnerable-node"
# The evidence sweep beat runs every minute (src/remediation/evidence.py).
EVIDENCE_RUN = "from src.remediation.evidence import build_due; print(build_due())"


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


def download(path: str) -> bytes:
    """A file from the dashboard, byte for byte."""
    try:
        with urllib.request.urlopen(f"{DASHBOARD}{path}", timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        fail(f"GET {path} returned {error.code}: {error.read().decode()[:300]}")
    raise AssertionError("unreachable")


def verify_with_openssl(name: str, data: bytes, signature_path: str, key_id: str) -> None:
    """Check a signature the way a reviewer would: openssl, the downloaded file and the public PEM, nothing else."""
    import base64
    import tempfile

    if shutil.which("openssl") is None:
        print(f"    {name}: signature not checked, openssl is not installed")
        return
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder)
        (work / "file").write_bytes(data)
        (work / "sig.der").write_bytes(base64.b64decode(download(signature_path)))
        (work / "key.pem").write_bytes(download(f"/api/signing-keys/{key_id.removeprefix('sha256:')}.pem"))
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", "key.pem", "-signature", "sig.der", "file"],
            cwd=work,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        fail(f"{name}: openssl could not verify the signature: {result.stdout.strip()} {result.stderr.strip()}")
    print(f"    {name}: signature verified by openssl ({key_id[:19]}...)")


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


def start_deployed() -> bool:
    """Run a container of the image under the name the stack scans, and let discovery record it."""
    subprocess.run(["docker", "rm", "-f", DEPLOYED], capture_output=True)
    scanned_name = f"{SCAN_HOST}/{REPO}"
    subprocess.run(["docker", "tag", f"{PUSH_HOST}/{REPO}", scanned_name], check=True)
    # The fixture's server prints a line and exits; keep the container up for discovery to see.
    run = ["docker", "run", "-d", "--name", DEPLOYED, "--entrypoint", "sleep", scanned_name, "3600"]
    subprocess.run(run, check=True, stdout=subprocess.DEVNULL)
    status = run_discovery()
    if status["status"] == "disabled":
        print("    skipped: runtime discovery is disabled")
        return False
    if status["status"] != "ok" or not status.get("deployments"):
        fail(f"discovery did not record containers: {status}")
    return True


def deployed_state(image_id: int) -> str:
    containers = request("GET", f"/api/images/{image_id}/deployments")["containers"]
    states = [item["state"] for item in containers if item["name"] == DEPLOYED]
    if len(states) != 1:
        fail(f"{DEPLOYED} is not among the image's containers: {[item['name'] for item in containers]}")
    return states[0]


def deployment_check(remediation_id: int, image_id: int) -> None:
    """The old container is stale and not on the fixed build; recreated from the new tag, it is."""
    run_discovery()
    deployment = request("GET", f"/api/remediations/{remediation_id}").get("deployment")
    if deployed_state(image_id) != "stale" or not deployment or DEPLOYED not in deployment["not_fixed"]:
        fail(f"the container started before the fix should be stale and not fixed: {deployment}")
    print(f"    before recreating: {deployment['fixed']} of {deployment['containers']} on the fixed build; stale")
    subprocess.run(["docker", "rm", "-f", DEPLOYED], check=True, stdout=subprocess.DEVNULL)
    start_deployed()
    deployment = request("GET", f"/api/remediations/{remediation_id}")["deployment"]
    if deployed_state(image_id) != "current" or DEPLOYED in deployment["not_fixed"]:
        fail(f"the recreated container should be current and fixed: {deployment}")
    print(f"    recreated: {deployment['fixed']} of {deployment['containers']} on the fixed build; current")


def remediation_half(scan: dict, target: dict, deployed: bool) -> None:
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

    step("download and verify the remediation's evidence")
    subprocess.run(  # what beat runs every minute
        ["docker", "compose", "exec", "-T", "celery-worker", "python", "-c", EVIDENCE_RUN],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    summary = request("GET", f"/api/remediations/{remediation_id}").get("evidence")
    if not summary or not summary.get("signed"):
        fail(f"remediation {remediation_id} has no signed evidence bundle: {summary}")
    bundle_bytes = download(f"/api/remediations/{remediation_id}/evidence")
    bundle = json.loads(bundle_bytes)
    if bundle["scans"]["after"] is None or bundle["scans"]["after"]["targets_present"]:
        fail(f"the evidence does not show the targets gone after the rescan: {bundle['scans']['after']}")
    if TARGET_CVE not in {target["cve_id"] for target in bundle["targets"]}:
        fail(f"the evidence does not list {TARGET_CVE} as a target")
    verify_with_openssl("evidence", bundle_bytes, f"/api/remediations/{remediation_id}/evidence.sig", summary["key_id"])

    if deployed:
        step("check the fix's deployment")
        deployment_check(remediation_id, image_id)


DISCOVERY_RUN = (
    "import json; from src.scan.tasks import discover_runtime_scans; print(json.dumps(discover_runtime_scans()))"
)


def run_discovery() -> dict:
    """One runtime discovery run in the worker: what beat triggers every 15 minutes."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "celery-worker", "python", "-c", DISCOVERY_RUN],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def discovery_check() -> None:
    """Discovery lists this stack's containers through docker-proxy, records them, and scans each once."""
    first = run_discovery()
    if first["status"] == "disabled":
        print("    skipped: runtime discovery is disabled")
        return
    if first["status"] != "ok":
        fail(f"runtime discovery failed: {first.get('error')}")
    second = run_discovery()
    if second["queued"]:
        fail(f"a second discovery run queued {second['queued']} scans; each running image should be queued once")
    if request("GET", "/api/system-status").get("discovery", {}).get("checked_at") != second["checked_at"]:
        fail("the system status does not show the last discovery run")
    running = {item["name"] for item in request("GET", "/api/images?running=true&limit=100")["items"]}
    if "postgres:16-alpine" not in running:
        fail(f"the stack's postgres:16-alpine is not marked running; running images: {sorted(running)}")
    built_here = sorted(name for name in running if name.startswith("scrutineering-"))
    if built_here:
        fail(f"images built on this host were recorded as scannable: {built_here}")
    print(
        f"    {second['running_images']} running images; skipped {second['local_only']} built here and "
        f"{second['id_only']} shown only by image ID; first run queued {first['queued']}, second run queued 0"
    )


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

    step("download the scan's SBOM")
    summary = request("GET", f"/api/scans/{scan_id}").get("sbom")
    if not summary:
        fail("the scan has no SBOM (see the worker log for the SBOM step)")
    sbom = request("GET", f"/api/scans/{scan_id}/sbom")
    if sbom.get("bomFormat") != "CycloneDX" or len(sbom.get("components") or []) < 1:
        fail("the downloaded SBOM is not a CycloneDX document with components")
    versions = {c.get("version") for c in sbom["components"] if c.get("name") == TARGET_PACKAGE}
    if target[0]["package_version"] not in versions:
        fail(f"the SBOM lists {TARGET_PACKAGE} {sorted(versions)}, not the scanned {target[0]['package_version']}")
    print(f"    CycloneDX {sbom['specVersion']}: {summary['components']} components, includes {TARGET_PACKAGE}")
    if not summary.get("signed"):
        fail("the SBOM is not signed (see the worker log: 'could not sign an SBOM')")
    verify_with_openssl(
        "SBOM", download(f"/api/scans/{scan_id}/sbom"), f"/api/scans/{scan_id}/sbom.sig", summary["key_id"]
    )

    step(f"start {DEPLOYED} from the unfixed image")
    try:
        deployed = start_deployed()
        remediation_half(scan, target[0], deployed)
        step("check notifications")
        notifications_check()
        step("check runtime discovery")
        discovery_check()
    finally:
        subprocess.run(["docker", "rm", "-f", DEPLOYED], capture_output=True)
    print("PASS: golden path (scan, fix, build, verify, rescan, complete, deployed, notify, discover)")


if __name__ == "__main__":
    main()
