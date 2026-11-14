#!/usr/bin/env node

const baseUrl = (process.env.SCAN_BASE_URL || "http://localhost:3001").replace(/\/$/, "");
const image = process.env.MILESTONE_IMAGE || process.env.SCAN_IMAGE || "alpine:3.20";
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 300000);
const pollMs = Number(process.env.SCAN_POLL_MS || 3000);
const directBackend = process.env.MILESTONE_API_MODE === "backend";
const scanPath = process.env.MILESTONE_SCAN_PATH || (directBackend ? "/api/dashboard/scans" : "/api/scans");
const headers = {
  "content-type": "application/json",
  ...(process.env.DASHBOARD_API_KEY ? { "x-api-key": process.env.DASHBOARD_API_KEY } : {}),
  ...(process.env.DASHBOARD_TRUSTED_PROXY_SECRET ? { "x-dashboard-proxy-secret": process.env.DASHBOARD_TRUSTED_PROXY_SECRET } : {}),
  "x-authenticated-roles": process.env.MILESTONE_ROLES || "admin,operator,remediator,security-operator",
};

async function request(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { ...headers, ...(init.headers || {}) } });
  const body = await response.text();
  let payload;
  try { payload = JSON.parse(body); } catch { payload = body; }
  if (!response.ok) throw new Error(`${path} returned ${response.status}: ${body}`);
  return payload;
}

async function runScan() {
  const started = Date.now();
  const submission = await request(scanPath, { method: "POST", body: JSON.stringify({ image_name: image, priority: "low" }) });
  let scan;
  while (Date.now() - started < timeoutMs) {
    scan = await request(`${scanPath}/${encodeURIComponent(submission.scan_id)}`);
    if (["completed", "partial", "failed", "cancelled"].includes(scan.status)) break;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  if (!scan || !["completed", "partial", "failed", "cancelled"].includes(scan.status)) throw new Error(`scan timed out: ${submission.scan_id}`);
  const findings = await request(`${scanPath}/${encodeURIComponent(submission.scan_id)}/findings?limit=200`);
  return { submission, scan, findings };
}

const started = Date.now();
const first = await runScan();
const second = await runScan();
const findings = first.findings;
const repeatedFindings = second.findings;
const result = {
  first_scan: first.scan,
  second_scan: second.scan,
  persisted_findings: findings.count,
  repeated_persisted_findings: repeatedFindings.count,
  findings_endpoint_verified: findings.scan_id === first.submission.scan_id && repeatedFindings.scan_id === second.submission.scan_id,
  repeat_scan_verified: first.scan.status === second.scan.status && findings.count === repeatedFindings.count,
  remediation_boundary: "available from scan detail via Propose fixes",
  elapsed_ms: Date.now() - started,
};
if (!result.findings_endpoint_verified) throw new Error("scan findings response did not preserve scan identity");
if (!result.repeat_scan_verified) throw new Error("repeat scan did not return stable terminal findings");
if (["failed", "cancelled"].includes(first.scan.status) || ["failed", "cancelled"].includes(second.scan.status)) throw new Error("live scan ended unsuccessfully");
console.log(JSON.stringify(result, null, 2));
