"use client";

import { useCallback, useEffect, useState } from "react";
import { getJson } from "@/lib/http";
import type { Page, ScanResult } from "@/types";

export const SCAN_STATUS_FILTERS = ["all", "pending", "running", "completed", "partial", "failed"] as const;
export type ScanStatusFilter = (typeof SCAN_STATUS_FILTERS)[number];
export type ScanHealth = { total: number; terminal_rate: number; degraded: boolean };

/** Paged, filterable scan history plus the recent-scan health summary. */
export function useScanHistory(pageSize: number) {
  const [page, setPage] = useState<Page<ScanResult> | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [filter, setFilterState] = useState<ScanStatusFilter>("all");
  const [search, setSearchState] = useState("");
  const [offset, setOffset] = useState(0);
  const [health, setHealth] = useState<ScanHealth | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    const query = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (filter !== "all") query.set("status", filter);
    if (search.trim()) query.set("search", search.trim());
    try {
      setPage(await getJson<Page<ScanResult>>(`/api/scans?${query}`));
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
    getJson<ScanHealth>("/api/scans/health?limit=100")
      .then(setHealth)
      .catch(() => setHealth(null));
  }, [filter, offset, pageSize, search]);

  useEffect(() => {
    reload();
  }, [reload]);

  // Changing the filter or search starts again from the first page.
  const setFilter = (value: ScanStatusFilter) => {
    setFilterState(value);
    setOffset(0);
  };
  const setSearch = (value: string) => {
    setSearchState(value);
    setOffset(0);
  };

  return { page, loading, failed, filter, setFilter, search, setSearch, offset, setOffset, health, reload };
}
