"use client";

import { useEffect, useState } from "react";
import { getJson } from "@/lib/http";

export type SystemStatus = {
  status: "operational" | "degraded" | "unavailable" | "checking";
  database?: string;
  queue?: string;
  workers: number;
  last_scan?: { scan_id: string; status: string; started_at: string | null; completed_at: string | null } | null;
  problems: string[];
  /** The last runtime discovery run within the hour, or null. */
  discovery?: {
    status: "ok" | "error" | "disabled";
    checked_at: string;
    error: string | null;
    running_images?: number;
    local_only?: number;
    id_only?: number;
    queued?: number;
  } | null;
};

const CHECKING: SystemStatus = { status: "checking", workers: 0, problems: [] };

/** Live service status from the API, refreshed every `intervalMs`; "unavailable" when the API itself is down. */
export function useSystemStatus(intervalMs = 30000): SystemStatus {
  const [status, setStatus] = useState<SystemStatus>(CHECKING);
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      getJson<SystemStatus>("/api/system-status")
        .then((next) => !cancelled && setStatus(next))
        .catch(() => !cancelled && setStatus({ status: "unavailable", workers: 0, problems: ["API unreachable"] }));
    load();
    const timer = window.setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [intervalMs]);
  return status;
}
