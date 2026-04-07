"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Layout from "@/components/Layout";
import FindingsTable from "@/components/FindingsTable";
import SeverityBadge from "@/components/SeverityBadge";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ImageDetail, VulnerabilityFinding } from "@/types";
import { Package, ArrowLeft, Filter, ExternalLink } from "lucide-react";
import Link from "next/link";

const SEVERITY_OPTIONS = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export default function ImageDetailPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const imageId = params.id as string;
  const initialSeverity = searchParams.get("severity") || "all";

  const [image, setImage] = useState<ImageDetail | null>(null);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState(initialSeverity);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const imgRes = await fetch(`/api/images/${imageId}`);
      const imgData = await imgRes.json();
      setImage(imgData.image || null);

      const findingsRes = await fetch(
        `/api/images/${imageId}${severityFilter !== "all" ? `?severity=${severityFilter}` : ""}`
      );
      const findingsData = await findingsRes.json();
      setFindings(findingsData.findings || []);
    } catch {
      setImage(null);
    }
    setLoading(false);
  }, [imageId, severityFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSeverityChange = (sev: string) => {
    setSeverityFilter(sev);
  };

  if (loading) return <Layout><LoadingSpinner /></Layout>;
  if (!image) return <Layout><EmptyState icon={Package} title="Image not found" description="No scan data exists for this image." /></Layout>;

  const filteredFindings = severityFilter !== "all"
    ? findings.filter((f) => f.severity === severityFilter)
    : findings;

  return (
    <Layout>
      {/* Breadcrumb */}
      <Link
        href="/dashboard"
        className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-blue-400 transition-colors mb-4"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to dashboard
      </Link>

      {/* Image header */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <Package className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold font-mono">
              {image.registry}/{image.repo_name}:{image.tag}
            </h2>
            {image.last_scan_at && (
              <p className="text-xs text-slate-500 mt-0.5">
                Last scanned: {new Date(image.last_scan_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4">
          {[
            { label: "Total Open", value: image.open_findings, color: "text-slate-100" },
            { label: "Critical", value: image.critical_count, color: "text-red-400" },
            { label: "High", value: image.high_count, color: "text-orange-400" },
            { label: "Medium", value: image.medium_count, color: "text-yellow-400" },
            { label: "Low", value: image.low_count, color: "text-slate-400" },
          ].map((stat) => (
            <div key={stat.label} className="bg-slate-900/50 rounded-lg px-3 py-2 text-center">
              <span className={`text-lg font-bold ${stat.color}`}>{stat.value}</span>
              <span className="text-xs text-slate-500 block">{stat.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Severity filter */}
      <div className="flex items-center gap-2 mb-4">
        <Filter className="w-4 h-4 text-slate-500" />
        <span className="text-sm text-slate-400 mr-1">Filter:</span>
        <div className="flex gap-1">
          {SEVERITY_OPTIONS.map((sev) => (
            <button
              key={sev}
              onClick={() => handleSeverityChange(sev)}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                severityFilter === sev
                  ? sev === "CRITICAL" ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : sev === "HIGH" ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                    : sev === "MEDIUM" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                    : "bg-slate-600/20 text-slate-300 border border-slate-600/30"
                  : "bg-slate-800 text-slate-500 hover:text-slate-300 border border-transparent"
              }`}
            >
              {sev === "all" ? "All" : (
                <><SeverityBadge severity={sev as any} /> </>
              )}
              {sev === "all" || sev}
            </button>
          ))}
        </div>
      </div>

      {/* Findings count */}
      <p className="text-sm text-slate-500 mb-3">
        Showing {filteredFindings.length} of {findings.length} findings
      </p>

      {/* Findings table */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
        <FindingsTable findings={filteredFindings} />
      </div>
    </Layout>
  );
}
