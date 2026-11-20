"use client";

import Link from "next/link";
import { useCallback, useState } from "react";
import { FileText, RefreshCw } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import ComplianceExportPanel from "@/components/reports/ComplianceExportPanel";
import LoadingSpinner from "@/components/LoadingSpinner";
import { useAsync } from "@/hooks/useAsync";
import { usePermissions } from "@/hooks/usePermissions";
import { getJson, postJson } from "@/lib/http";
import { cx } from "@/lib/cx";
import type { ReportSummary } from "@/types";

function periodLabel(report: Pick<ReportSummary, "period_start" | "period_end">): string {
  const day = (value: string) => new Date(value).toLocaleDateString(undefined, { timeZone: "UTC" });
  return `${day(report.period_start)} – ${day(report.period_end)}`;
}

export default function ReportsPage() {
  const permissions = usePermissions();
  const roles = Array.isArray(permissions.roles) ? (permissions.roles as string[]) : [];
  const isAdmin = roles.includes("admin");
  const canExport = isAdmin || roles.includes("security-operator");
  const [notice, setNotice] = useState<string | null>(null);
  const loadReports = useCallback(() => getJson<{ items: ReportSummary[] }>("/api/reports"), []);
  const reports = useAsync(loadReports);

  async function buildNow() {
    setNotice("Queued. The worker builds it within a few seconds; refresh to see it.");
    try {
      await postJson("/api/reports");
    } catch (error) {
      setNotice(`Couldn't queue a report: ${(error as Error).message}`);
    }
  }

  if (reports.loading && !reports.data)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  const items = reports.data?.items ?? [];
  return (
    <Layout>
      <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="eyebrow mb-3">Governance / Reports</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Reports</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            A signed report every Monday covers the week before (UTC): posture, what changed, fixes, and containers
            still on an older build.
          </p>
        </div>
        <div className="flex gap-2">
          {isAdmin && (
            <button
              onClick={buildNow}
              className="rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300"
            >
              Build report now
            </button>
          )}
          <button
            onClick={reports.reload}
            className={cx(
              "inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5",
              "text-sm text-slate-300 hover:text-white",
            )}
          >
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
        </div>
      </div>
      {notice && <p className="mb-4 text-sm text-cyan-200">{notice}</p>}
      {reports.error && <p className="mb-4 text-sm text-amber-200">{reports.error}</p>}
      <section className="panel overflow-hidden rounded-2xl">
        <div className="divide-y divide-slate-800/70">
          {items.map((report) => (
            <Link
              key={report.id}
              href={`/reports/${report.id}`}
              className="flex items-center justify-between gap-3 p-5 transition hover:bg-slate-800/30 sm:px-6"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300">
                  <FileText className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-200">{periodLabel(report)}</div>
                  <div className="text-xs text-slate-500">
                    {report.kind === "weekly" ? "Weekly" : "On demand"} · built{" "}
                    {new Date(report.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
              <span className="text-xs text-slate-500">{report.signed ? "signed" : "unsigned"}</span>
            </Link>
          ))}
          {!items.length && (
            <EmptyState
              icon={FileText}
              title="No reports yet"
              description="The first weekly report is built next Monday at 07:00 UTC."
            />
          )}
        </div>
      </section>
      {canExport && <ComplianceExportPanel />}
    </Layout>
  );
}
