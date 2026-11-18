"use client";

import { useAsync } from "@/hooks/useAsync";
import { getJson } from "@/lib/http";
import type { DashboardSession, ImageDetail, Page, PostureSummary, ScanResult, SeverityTrend } from "@/types";

export const EMPTY_POSTURE: PostureSummary = {
  total_scanned_images: 0,
  total_findings: 0,
  critical_count: 0,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
  fixable_count: 0,
  last_scan_at: null,
  last_scan_status: null,
};

type Overview = {
  posture: PostureSummary;
  trends: SeverityTrend[];
  scans: ScanResult[];
  images: ImageDetail[];
  refreshedAt: Date;
};

async function loadOverview(): Promise<Overview> {
  const [posture, trends, scanPage, imagePage] = await Promise.all([
    getJson<PostureSummary>("/api/posture/summary"),
    getJson<SeverityTrend[]>("/api/posture/trend"),
    getJson<Page<ScanResult>>("/api/scans"),
    getJson<Page<ImageDetail>>("/api/images"),
  ]);
  return { posture, trends, scans: scanPage.items, images: imagePage.items, refreshedAt: new Date() };
}

async function loadSession(): Promise<DashboardSession | null> {
  return getJson<DashboardSession>("/api/session").catch(() => null);
}

/** Posture, trend, recent scans, tracked images, and the session for the overview page. */
export function useDashboardData() {
  const overview = useAsync(loadOverview);
  const session = useAsync(loadSession);
  return {
    posture: overview.data?.posture ?? EMPTY_POSTURE,
    trends: overview.data?.trends ?? [],
    scans: overview.data?.scans ?? [],
    images: overview.data?.images ?? [],
    session: session.data ?? null,
    loading: overview.loading,
    error: overview.error ? "The dashboard data service is unavailable. Try refreshing in a moment." : null,
    refreshedAt: overview.data?.refreshedAt ?? null,
    reload: overview.reload,
  };
}
