"use client";

import { useCallback, useState } from "react";
import { useAsync } from "@/hooks/useAsync";
import { getJson } from "@/lib/http";
import type { Page, ScanResult } from "@/types";

export const SCAN_STATUS_FILTERS = ["all", "pending", "running", "completed", "partial", "failed"] as const;
export type ScanStatusFilter = (typeof SCAN_STATUS_FILTERS)[number];
export type ScanHealth = { total: number; terminal_rate: number; degraded: boolean };

async function loadHealth(): Promise<ScanHealth | null> {
  return getJson<ScanHealth>("/api/scans/health?limit=100").catch(() => null);
}

/** Paged, filterable scan history plus the recent-scan health summary. */
export function useScanHistory(pageSize: number) {
  const [filter, setFilterState] = useState<ScanStatusFilter>("all");
  const [search, setSearchState] = useState("");
  const [offset, setOffset] = useState(0);

  const loadPage = useCallback(() => {
    const query = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (filter !== "all") query.set("status", filter);
    if (search.trim()) query.set("search", search.trim());
    return getJson<Page<ScanResult>>(`/api/scans?${query}`);
  }, [filter, offset, pageSize, search]);
  const history = useAsync(loadPage);
  const health = useAsync(loadHealth);

  const { reload: reloadHistory } = history;
  const { reload: reloadHealth } = health;
  const reload = useCallback(() => {
    reloadHistory();
    reloadHealth();
  }, [reloadHistory, reloadHealth]);

  // Changing the filter or search starts again from the first page.
  const setFilter = (value: ScanStatusFilter) => {
    setFilterState(value);
    setOffset(0);
  };
  const setSearch = (value: string) => {
    setSearchState(value);
    setOffset(0);
  };

  return {
    page: history.data ?? null,
    loading: history.loading,
    failed: Boolean(history.error),
    filter,
    setFilter,
    search,
    setSearch,
    offset,
    setOffset,
    health: health.data ?? null,
    reload,
  };
}
