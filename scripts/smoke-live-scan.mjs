#!/usr/bin/env node

const baseUrl = (process.env.SCAN_BASE_URL || "http://localhost:3001").replace(/\/$/, "");
const image = process.env.SCAN_IMAGE || "alpine:3.20";
const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 300000);
const pollMs = Number(process.env.SCAN_POLL_MS || 3000);
const started = Date.now();
const response = await fetch(`${baseUrl}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_name: image, priority: "low" }) });
if (!response.ok) throw new Error(`scan submission failed: ${response.status} ${await response.text()}`);
const submission = await response.json();
if (!submission.scan_id) throw new Error("scan submission did not return scan_id");
let result;
while (Date.now() - started < timeoutMs) {
  const status = await fetch(`${baseUrl}/api/scans/${encodeURIComponent(submission.scan_id)}`, { cache: "no-store" });
  if (!status.ok) throw new Error(`scan status failed: ${status.status}`);
  result = await status.json();
  if (["completed", "partial", "failed", "cancelled"].includes(result.status)) break;
  await new Promise((resolve) => setTimeout(resolve, pollMs));
}
if (!result || !["completed", "partial", "failed", "cancelled"].includes(result.status)) throw new Error(`scan timed out: ${submission.scan_id}`);
if (result.status === "failed" || result.status === "cancelled") throw new Error(`live scan ended ${result.status}: ${submission.scan_id}`);
const metrics = await fetch(process.env.SCAN_METRICS_URL || "http://localhost:8000/metrics");
const metricsBody = await metrics.text();
if (!metrics.ok || !metricsBody.includes('scrutineering_persisted_scans{status="completed"}')) throw new Error("scan metrics are unavailable or missing persisted status");
console.log(JSON.stringify({ submission, result, metrics_available: true, elapsed_ms: Date.now() - started }, null, 2));
