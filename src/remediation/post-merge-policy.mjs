export function evaluatePostMerge({ expectedDigest, observedDigest, scanStatus, before, after }) {
  const reasons = [];
  if (!expectedDigest || expectedDigest !== observedDigest) reasons.push("digest_drift");
  if (scanStatus !== "completed") reasons.push("scan_incomplete");
  if (after > before) reasons.push("finding_regression");
  return { status: reasons.length ? "rollback_required" : "verified", reasons };
}
