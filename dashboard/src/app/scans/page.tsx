"use client";

import { useEffect, useState } from "react";
import Layout from "@/components/Layout";
import SeverityBadge from "@/components/SeverityBadge";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ScanResult } from "@/types";
import { CheckCircle2, XCircle, AlertOctagon, Clock, ScanLine, Search, Filter } from "lucide-react";
import Link from "next/link";

const STATUS_FILTERS = ["all", "completed", "failed", "partial"] as const;

export default function ScansPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<typeof STATUS_FILTERS[number]>("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetch("/api/scans")
      .then((r) => r.json())
      .then((data) => {
        setScans(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filtered = scans.filter((s) => {
    if (filter !== "all" && s.status !== filter) return false;
    if (search && !s.image_name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  if (loading) return <Layout><LoadingSpinner /></Layout>;
  if (!scans.length) return <Layout><EmptyState icon={ScanLine} title="No scans yet" description="Run your first container scan to see results here." /></Layout>;

  return (
    <Layout>
      <div className="mb-6">
        <h2 className="text-2xl font-bold tracking-tight">Scan History</h2>
        <p className="text-slate-400 mt-1">Timeline of container vulnerability scans</p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by image name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <div className="flex gap-1 bg-slate-800 rounded-lg p-1 border border-slate-700">
          {STATUS_FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors capitalize ${
                filter === f
                  ? "bg-blue-600 text-white"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 && (
        <EmptyState
          icon={Filter}
          title="No matching scans"
          description="Try adjusting your filters or search term."
        />
      )}

      {/* Timeline */}
      <div className="space-y-4">
        {filtered.map((scan, idx) => {
          const isCompleted = scan.status === "completed";
          const isFailed = scan.status === "failed";
          const isPartial = scan.status === "partial";
          const duration = scan.started_at && scan.completed_at
            ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 60000)
            : null;

          return (
            <div
              key={scan.scan_id}
              className="relative bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 hover:border-slate-600 transition-colors"
            >
              {/* Timeline connector */}
              {idx < filtered.length - 1 && (
                <div className="absolute left-8 top-full w-0.5 h-4 bg-slate-700" />
              )}

              <div className="flex items-start gap-4">
                {/* Status icon */}
                <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
                  isCompleted ? "bg-emerald-500/20 text-emerald-400" :
                  isPartial ? "bg-amber-500/20 text-amber-400" :
                  "bg-red-500/20 text-red-400"
                }`}>
                  {isCompleted && <CheckCircle2 className="w-5 h-5" />}
                  {isPartial && <AlertOctagon className="w-5 h-5" />}
                  {isFailed && <XCircle className="w-5 h-5" />}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-sm font-mono text-blue-300 bg-blue-500/10 px-2 py-0.5 rounded">
                      {scan.image_name}
                    </code>
                    <SeverityBadge severity={isCompleted ? "LOW" : isPartial ? "MEDIUM" : "CRITICAL"} />
                  </div>

                  <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                    <div>
                      <span className="text-slate-500 block">Scan ID</span>
                      <span className="text-slate-300 font-mono">{scan.scan_id}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Started</span>
                      <span className="text-slate-300">
                        <Clock className="inline w-3 h-3 mr-1 -mt-0.5" />
                        {new Date(scan.started_at).toLocaleString()}
                      </span>
                    </div>
                    {duration !== null && (
                      <div>
                        <span className="text-slate-500 block">Duration</span>
                        <span className="text-slate-300">{duration} min</span>
                      </div>
                    )}
                    <div>
                      <span className="text-slate-500 block">Findings</span>
                      <span className="text-slate-300">
                        {scan.critical_count + scan.high_count + scan.medium_count + scan.low_count} total
                      </span>
                    </div>
                  </div>

                  {/* Severity breakdown */}
                  <div className="mt-3 flex gap-3 text-xs">
                    {scan.critical_count > 0 && (
                      <span className="text-red-400 bg-red-500/10 px-2 py-1 rounded">
                        {scan.critical_count} critical
                      </span>
                    )}
                    {scan.high_count > 0 && (
                      <span className="text-orange-400 bg-orange-500/10 px-2 py-1 rounded">
                        {scan.high_count} high
                      </span>
                    )}
                    {scan.medium_count > 0 && (
                      <span className="text-yellow-400 bg-yellow-500/10 px-2 py-1 rounded">
                        {scan.medium_count} medium
                      </span>
                    )}
                    {scan.low_count > 0 && (
                      <span className="text-slate-400 bg-slate-500/10 px-2 py-1 rounded">
                        {scan.low_count} low
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary footer */}
      <div className="mt-8 pt-4 border-t border-slate-800 text-xs text-slate-500 flex justify-between">
        <span>{filtered.length} scan{filtered.length !== 1 ? "s" : ""} shown</span>
        <span>
          {scans.filter(s => s.status === "completed").length} completed · {scans.filter(s => s.status === "partial").length} partial · {scans.filter(s => s.status === "failed").length} failed
        </span>
      </div>
    </Layout>
  );
}
