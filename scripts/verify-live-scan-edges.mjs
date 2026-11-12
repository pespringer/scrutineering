#!/usr/bin/env node

const base = (process.env.SCAN_BASE_URL || "http://localhost:3001").replace(/\/$/, "");
const timeoutMs = Number(process.env.SCAN_EDGE_TIMEOUT_MS || 180000);
const pollMs = Number(process.env.SCAN_POLL_MS || 3000);

async function submit(image) {
  const response = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_name: image, priority: "low" }) });
  if (!response.ok) throw new Error(`submit ${image}: ${response.status} ${await response.text()}`);
  return response.json();
}

async function poll(scanId) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const response = await fetch(`${base}/api/scans/${encodeURIComponent(scanId)}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`status ${scanId}: ${response.status}`);
    const result = await response.json();
    if (["completed", "partial", "failed", "cancelled"].includes(result.status)) return result;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`timeout ${scanId}`);
}

const failure = await submit(process.env.SCAN_FAILURE_IMAGE || "invalid.invalid/scrutineering/not-found:never");
const failed = await poll(failure.scan_id);
if (failed.status !== "failed") throw new Error(`expected failed scan, got ${failed.status}`);

const cancellation = await submit(process.env.SCAN_CANCEL_IMAGE || "alpine:3.20");
const cancelResponse = await fetch(`${base}/api/scans/${encodeURIComponent(cancellation.scan_id)}`, { method: "POST" });
if (!cancelResponse.ok) throw new Error(`cancel ${cancellation.scan_id}: ${cancelResponse.status}`);
const canceled = await poll(cancellation.scan_id);
if (canceled.status !== "cancelled") throw new Error(`expected cancelled scan, got ${canceled.status}`);
console.log(JSON.stringify({ failure: failed, cancellation: canceled }, null, 2));
