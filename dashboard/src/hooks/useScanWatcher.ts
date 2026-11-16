"use client";

import { useEffect } from "react";
import { getJson } from "@/lib/http";
import { isTerminalScan } from "@/lib/status";
import type { ScanResult } from "@/types";

/** Poll one scan until it reaches a terminal state (including `partial`), then report it once. */
export function useScanWatcher(scanId: string | null, onFinished: (scan: ScanResult) => void, intervalMs = 3000) {
  useEffect(() => {
    if (!scanId) return;
    let stopped = false;
    const timer = window.setInterval(async () => {
      try {
        const scan = await getJson<ScanResult>(`/api/scans/${scanId}`);
        if (!stopped && isTerminalScan(scan.status)) {
          stopped = true;
          window.clearInterval(timer);
          onFinished(scan);
        }
      } catch {
        // Keep polling: the API may be restarting.
      }
    }, intervalMs);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [scanId, onFinished, intervalMs]);
}
