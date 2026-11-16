/** Scan and remediation states shared by the dashboard pages. */

export const TERMINAL_SCAN_STATUSES = ["completed", "partial", "failed", "cancelled"] as const;

export function isTerminalScan(status: string): boolean {
  return (TERMINAL_SCAN_STATUSES as readonly string[]).includes(status);
}

export function isActiveScan(status: string): boolean {
  return status === "pending" || status === "running";
}

/** Badge colors for remediation, publication, and verification states. */
export function statusTone(status: string | null | undefined): string {
  if (status === "verified" || status === "completed" || status === "ready") {
    return "bg-emerald-400/10 text-emerald-200";
  }
  if (status === "rollback_required" || status === "failed" || status === "blocked") {
    return "bg-rose-400/10 text-rose-200";
  }
  return "bg-amber-400/10 text-amber-200";
}
