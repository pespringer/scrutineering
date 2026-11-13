#!/usr/bin/env node

const baseUrl = (process.env.SCAN_BASE_URL || "http://localhost:8000").replace(/\/$/, "");
const image = process.env.MILESTONE_IMAGE || process.env.SCAN_IMAGE || "alpine:3.20";
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 300000);
const pollMs = Number(process.env.SCAN_POLL_MS || 3000);
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

const started = Date.now();
const submission = await request("/api/dashboard/scans", { method: "POST", body: JSON.stringify({ image_name: image, priority: "low" }) });
let scan;
while (Date.now() - started < timeoutMs) {
  scan = await request(`/api/dashboard/scans/${encodeURIComponent(submission.scan_id)}`);
  if (["completed", "partial", "failed", "cancelled"].includes(scan.status)) break;
  await new Promise((resolve) => setTimeout(resolve, pollMs));
}
if (!scan || !["completed", "partial", "failed", "cancelled"].includes(scan.status)) throw new Error(`scan timed out: ${submission.scan_id}`);
const findings = await request(`/api/dashboard/scans/${encodeURIComponent(submission.scan_id)}/findings?limit=200`);
const result = {
  submission,
  scan,
  persisted_findings: findings.count,
  findings_endpoint_verified: findings.scan_id === submission.scan_id,
  remediation_boundary: "available from scan detail via Propose fixes",
  elapsed_ms: Date.now() - started,
};
if (!result.findings_endpoint_verified) throw new Error("scan findings response did not preserve scan identity");
if (["failed", "cancelled"].includes(scan.status)) throw new Error(`live scan ended ${scan.status}`);
console.log(JSON.stringify(result, null, 2));
