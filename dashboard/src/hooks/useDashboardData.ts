"use client";

import { useCallback, useEffect, useState } from "react";
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

/** Posture, trend, recent scans, tracked images, and the session for the overview page. */
export function useDashboardData() {
  const [posture, setPosture] = useState<PostureSummary>(EMPTY_POSTURE);
  const [trends, setTrends] = useState<SeverityTrend[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [images, setImages] = useState<ImageDetail[]>([]);
  const [session, setSession] = useState<DashboardSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summary, trend, scanPage, imagePage] = await Promise.all([
        getJson<PostureSummary>("/api/posture/summary"),
        getJson<SeverityTrend[]>("/api/posture/trend"),
        getJson<Page<ScanResult>>("/api/scans"),
        getJson<Page<ImageDetail>>("/api/images"),
      ]);
      setPosture(summary);
      setTrends(trend);
      setScans(scanPage.items);
      setImages(imagePage.items);
      setRefreshedAt(new Date());
    } catch {
      setError("The dashboard data service is unavailable. Try refreshing in a moment.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    getJson<DashboardSession>("/api/session")
      .then(setSession)
      .catch(() => setSession(null));
  }, [reload]);

  return { posture, trends, scans, images, session, loading, error, refreshedAt, reload };
}
