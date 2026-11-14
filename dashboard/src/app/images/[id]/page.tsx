"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Layout from "@/components/Layout";
import FindingsTable from "@/components/FindingsTable";
import SeverityBadge from "@/components/SeverityBadge";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ImageDetail, VulnerabilityFinding } from "@/types";
import { Package, ArrowLeft, Filter, ExternalLink, Check, ShieldCheck, ShieldOff } from "lucide-react";
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
  const [findingsOffset, setFindingsOffset] = useState(0);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [selectedFindings, setSelectedFindings] = useState<number[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [schedule, setSchedule] = useState<{ configured: boolean; enabled: boolean; interval_seconds: number | null; next_run_at: string | null }>({ configured: false, enabled: false, interval_seconds: null, next_run_at: null });
  const FINDINGS_PAGE_SIZE = 25;

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const imgRes = await fetch(`/api/images/${imageId}`);
      const imgData = await imgRes.json();
      setImage(imgData.image || null);

      const findingsRes = await fetch(
        `/api/images/${imageId}?${new URLSearchParams({ ...(severityFilter !== "all" ? { severity: severityFilter } : {}), limit: String(FINDINGS_PAGE_SIZE), offset: String(findingsOffset) })}`
      );
      const findingsData = await findingsRes.json();
      setFindings(findingsData.findings || []);
      setFindingsTotal(findingsData.findings_page?.total ?? findingsData.findings?.length ?? 0);
      try {
        const scheduleRes = await fetch(`/api/images/${imageId}/schedule`, { cache: "no-store" });
        if (scheduleRes.ok) setSchedule((await scheduleRes.json()).schedule);
      } catch { /* schedule controls remain at their safe default */ }
    } catch {
      setImage(null);
    }
    setLoading(false);
  }, [imageId, severityFilter, findingsOffset]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => { fetch("/api/permissions", { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then((permissions) => setCanManage(Boolean(permissions?.can_manage_scans))).catch(() => undefined); }, []);

  async function acknowledgeSelected() {
    if (!selectedFindings.length) return;
    const response = await fetch("/api/findings/bulk-acknowledge", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ids: selectedFindings }) });
    setNotice(response.ok ? "Selected findings acknowledged." : "Unable to acknowledge findings.");
    if (response.ok) { setSelectedFindings([]); loadData(); }
  }

  async function suppressSelected() {
    if (!selectedFindings.length) return;
    const reason = window.prompt("Why should these findings be suppressed? (required)");
    if (!reason?.trim()) return;
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const response = await fetch("/api/findings/suppress", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ finding_ids: selectedFindings, reason: reason.trim(), expires_at: expires }) });
    setNotice(response.ok ? "Selected findings suppressed for 30 days." : "Unable to suppress findings.");
    if (response.ok) { setSelectedFindings([]); loadData(); }
  }

  async function unsuppressSelected() {
    if (!selectedFindings.length) return;
    const response = await fetch("/api/findings/unsuppress", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ids: selectedFindings }) });
    setNotice(response.ok ? "Selected finding suppressions revoked." : "Unable to revoke suppressions.");
    if (response.ok) { setSelectedFindings([]); loadData(); }
  }

  async function updateSchedule(enabled: boolean, intervalSeconds: number) {
    const response = await fetch(`/api/images/${imageId}/schedule`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled, interval_seconds: intervalSeconds }) });
    if (!response.ok) { setNotice("Unable to update the scan schedule."); return; }
    setSchedule((await response.json()).schedule);
    setNotice(enabled ? "Recurring scanning enabled." : "Recurring scanning paused.");
  }

  const handleSeverityChange = (sev: string) => {
    setSeverityFilter(sev);
    setFindingsOffset(0);
  };

  if (loading) return <Layout><LoadingSpinner /></Layout>;
  if (!image) return <Layout><EmptyState icon={Package} title="Image not found" description="No scan data exists for this image." /></Layout>;

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
      <div className="panel relative mb-6 overflow-hidden rounded-3xl p-6 sm:p-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.08]">
            <Package className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h2 className="break-all font-mono text-xl font-semibold tracking-tight text-white sm:text-2xl">
              {image.registry}/{image.repo_name}:{image.tag}
            </h2>
            {image.last_scan_at && (
              <p className="mt-1 text-xs text-slate-500">
                Last scanned: {new Date(image.last_scan_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>

        {/* Stats row */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-5">
          {[
            { label: "Total Open", value: image.open_findings, color: "text-slate-100" },
            { label: "Critical", value: image.critical_count, color: "text-red-400" },
            { label: "High", value: image.high_count, color: "text-orange-400" },
            { label: "Medium", value: image.medium_count, color: "text-yellow-400" },
            { label: "Low", value: image.low_count, color: "text-slate-400" },
          ].map((stat) => (
            <div key={stat.label} className="rounded-xl border border-slate-700/60 bg-slate-950/40 px-3 py-3 text-center">
              <span className={`text-lg font-bold ${stat.color}`}>{stat.value}</span>
              <span className="text-xs text-slate-500 block">{stat.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel mb-6 flex flex-col gap-4 rounded-2xl p-5 sm:flex-row sm:items-center sm:justify-between">
        <div><div className="eyebrow mb-1">Automated scanning</div><p className="text-sm text-slate-400">{schedule.enabled ? `Runs every ${formatInterval(schedule.interval_seconds)}${schedule.next_run_at ? ` · next run ${new Date(schedule.next_run_at).toLocaleString()}` : ""}` : "Recurring scanning is paused for this image."}</p></div>
        {canManage && <div className="flex flex-wrap items-center gap-2"><select aria-label="Scan interval" value={schedule.interval_seconds || 21600} onChange={(event) => updateSchedule(true, Number(event.target.value))} className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"><option value="3600">Every hour</option><option value="21600">Every 6 hours</option><option value="43200">Every 12 hours</option><option value="86400">Daily</option><option value="604800">Weekly</option></select><button onClick={() => updateSchedule(!schedule.enabled, schedule.interval_seconds || 21600)} className="rounded-xl border border-cyan-400/30 px-3 py-2 text-sm text-cyan-200 hover:bg-cyan-400/10">{schedule.enabled ? "Pause" : "Enable"}</button></div>}
      </div>

      {/* Severity filter */}
      <div className="mb-5 flex flex-wrap items-center gap-2">
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
      <p className="mb-3 text-sm text-slate-500">
        Showing {findingsOffset + (findings.length ? 1 : 0)}–{findingsOffset + findings.length} of {findingsTotal} findings
      </p>

      {/* Findings table */}
      {canManage && selectedFindings.length > 0 && <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-xs text-cyan-200"><span>{selectedFindings.length} selected</span><button onClick={acknowledgeSelected} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 px-2.5 py-1.5"><Check className="h-3.5 w-3.5" /> Acknowledge</button><button onClick={suppressSelected} className="inline-flex items-center gap-1 rounded-lg border border-amber-400/30 px-2.5 py-1.5 text-amber-200"><ShieldOff className="h-3.5 w-3.5" /> Suppress 30 days</button><button onClick={unsuppressSelected} className="inline-flex items-center gap-1 rounded-lg border border-emerald-400/30 px-2.5 py-1.5 text-emerald-200"><ShieldCheck className="h-3.5 w-3.5" /> Revoke suppression</button><button onClick={() => setSelectedFindings([])} className="text-slate-400">Clear</button></div>}
      {notice && <p className="mb-3 text-sm text-cyan-200">{notice}</p>}
      <div className="panel rounded-2xl p-4 sm:p-6">
        <FindingsTable findings={findings} selectable={canManage} selected={selectedFindings} onSelect={(id, checked) => setSelectedFindings((current) => checked ? [...new Set([...current, id])] : current.filter((value) => value !== id))} />
      </div>
      <div className="mt-4 flex justify-end gap-3 text-xs"><button disabled={findingsOffset === 0} onClick={() => setFindingsOffset(Math.max(0, findingsOffset - FINDINGS_PAGE_SIZE))} className="text-cyan-300 disabled:text-slate-700">Previous</button><button disabled={findingsOffset + FINDINGS_PAGE_SIZE >= findingsTotal} onClick={() => setFindingsOffset(findingsOffset + FINDINGS_PAGE_SIZE)} className="text-cyan-300 disabled:text-slate-700">Next</button></div>
    </Layout>
  );
}

function formatInterval(seconds: number | null) {
  if (!seconds) return "configured cadence";
  if (seconds % 604800 === 0) return `${seconds / 604800} week${seconds === 604800 ? "" : "s"}`;
  if (seconds % 86400 === 0) return `${seconds / 86400} day${seconds === 86400 ? "" : "s"}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  return `${Math.round(seconds / 60)} minutes`;
}
