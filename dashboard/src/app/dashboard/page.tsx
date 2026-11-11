"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle, AlertTriangle, ArrowRight, CheckCircle2, ChevronRight, Clock3,
  Info, Package, RefreshCw, ShieldAlert, Sparkles, TrendingUp,
} from "lucide-react";
import {
  CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import StatCard from "@/components/StatCard";
import type { ImageDetail, Page, PostureSummary, ScanResult, SeverityTrend } from "@/types";

const EMPTY_POSTURE: PostureSummary = {
  total_scanned_images: 0, total_findings: 0, critical_count: 0,
  high_count: 0, medium_count: 0, low_count: 0, fixable_count: 0,
  last_scan_at: null, last_scan_status: null,
};

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

function items<T>(page: T[] | Page<T>): T[] {
  return Array.isArray(page) ? page : page.items;
}

export default function DashboardPage() {
  const [posture, setPosture] = useState<PostureSummary>(EMPTY_POSTURE);
  const [trends, setTrends] = useState<SeverityTrend[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [images, setImages] = useState<ImageDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);
    const api = process.env.NEXT_PUBLIC_API_URL || "";
    try {
      const [summary, trend, scanHistory, trackedImages] = await Promise.all([
        getJson<PostureSummary>(`${api}/api/posture/summary`),
        getJson<SeverityTrend[]>(`${api}/api/posture/trend`),
        getJson<ScanResult[] | Page<ScanResult>>(`${api}/api/scans`),
        getJson<ImageDetail[] | Page<ImageDetail>>(`${api}/api/images`),
      ]);
      setPosture(summary); setTrends(trend); setScans(items(scanHistory)); setImages(items(trackedImages));
    } catch {
      if (api) {
        try {
          const [summary, trend, scanHistory, trackedImages] = await Promise.all([
            getJson<PostureSummary>("/api/posture/summary"), getJson<SeverityTrend[]>("/api/posture/trend"),
            getJson<ScanResult[] | Page<ScanResult>>("/api/scans"), getJson<ImageDetail[] | Page<ImageDetail>>("/api/images"),
          ]);
          setPosture(summary); setTrends(trend); setScans(items(scanHistory)); setImages(items(trackedImages));
        } catch { setError("The dashboard data service is unavailable. Try refreshing in a moment."); }
      } else setError("The dashboard data service is unavailable. Try refreshing in a moment.");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { loadDashboard(); }, [loadDashboard]);

  const riskTotal = Math.max(posture.critical_count + posture.high_count + posture.medium_count + posture.low_count, 1);
  const risk = useMemo(() => [
    { label: "Critical", count: posture.critical_count, color: "#ff647c", width: `${(posture.critical_count / riskTotal) * 100}%` },
    { label: "High", count: posture.high_count, color: "#ff9f5b", width: `${(posture.high_count / riskTotal) * 100}%` },
    { label: "Medium", count: posture.medium_count, color: "#f5cf6b", width: `${(posture.medium_count / riskTotal) * 100}%` },
    { label: "Low", count: posture.low_count, color: "#55a6ff", width: `${(posture.low_count / riskTotal) * 100}%` },
  ], [posture, riskTotal]);

  if (loading) return <Layout><LoadingSpinner /></Layout>;

  return (
    <Layout>
      <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div><div className="eyebrow mb-3 flex items-center gap-2"><span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Security operations</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Good morning, sentinel.</h1><p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">One view of your container estate, its exposure, and the work that needs attention next.</p></div>
        <button onClick={loadDashboard} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh data</button>
      </div>

      {error && <div className="mb-6 flex items-center gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/[0.07] px-4 py-3 text-sm text-amber-200"><Info className="h-4 w-4 shrink-0" />{error}<button onClick={loadDashboard} className="ml-auto font-semibold underline underline-offset-4">Retry</button></div>}

      <section className="panel relative mb-6 overflow-hidden rounded-3xl p-6 sm:p-8">
        <div className="absolute -right-24 -top-32 h-80 w-80 rounded-full bg-cyan-400/10 blur-3xl" />
        <div className="relative flex flex-col justify-between gap-8 lg:flex-row lg:items-center">
          <div className="max-w-xl"><div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-300/15 bg-cyan-300/[0.07] px-3 py-1.5 text-xs font-medium text-cyan-200"><Sparkles className="h-3.5 w-3.5" /> Continuous protection enabled</div><h2 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">Your estate is being watched.</h2><p className="mt-3 text-sm leading-6 text-slate-400">{posture.total_scanned_images} images are under management. Close the loop on {posture.fixable_count} fixable findings to reduce your active exposure.</p></div>
          <div className="flex shrink-0 items-center gap-6"><div className="relative flex h-32 w-32 items-center justify-center rounded-full" style={{ background: `conic-gradient(#38d39f ${Math.max(12, 100 - Math.min(88, posture.total_findings * 2))}%, #1b2a3b 0)` }}><div className="flex h-24 w-24 flex-col items-center justify-center rounded-full bg-[#101925]"><span className="text-2xl font-bold text-white">{posture.total_findings}</span><span className="text-[10px] uppercase tracking-wider text-slate-500">open issues</span></div></div><div><div className="text-sm font-medium text-slate-200">Risk snapshot</div><div className="mt-2 flex items-center gap-2 text-xs text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" /> Monitoring active</div><div className="mt-1 text-xs text-slate-500">Last scan {posture.last_scan_at ? new Date(posture.last_scan_at).toLocaleDateString() : "never"}</div></div></div>
        </div>
      </section>

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 lg:gap-4">
        <StatCard label="Images" value={posture.total_scanned_images} detail="in your estate" icon={<Package className="h-4 w-4" />} color="blue" />
        <StatCard label="Open findings" value={posture.total_findings} detail="across all images" icon={<ShieldAlert className="h-4 w-4" />} />
        <StatCard label="Critical" value={posture.critical_count} detail="needs immediate action" icon={<AlertCircle className="h-4 w-4" />} color="red" />
        <StatCard label="High" value={posture.high_count} detail="priority exposure" icon={<AlertTriangle className="h-4 w-4" />} color="orange" />
        <StatCard label="Fixable" value={posture.fixable_count} detail="with known upgrades" icon={<TrendingUp className="h-4 w-4" />} color="green" />
        <StatCard label="Scan status" value={posture.last_scan_status || "—"} detail="most recent run" icon={<CheckCircle2 className="h-4 w-4" />} color="blue" />
      </div>

      <div className="mb-6 grid gap-6 xl:grid-cols-[1.45fr_0.85fr]">
        <section className="panel rounded-2xl p-5 sm:p-6"><div className="mb-6 flex items-start justify-between"><div><div className="eyebrow mb-2">Exposure over time</div><h3 className="text-lg font-semibold text-white">Severity trend</h3></div><div className="rounded-lg border border-slate-700/70 px-2.5 py-1 text-xs text-slate-500">Last 30 days</div></div>{trends.length ? <div className="h-[280px] w-full"><ResponsiveContainer width="100%" height="100%"><LineChart data={trends} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}><CartesianGrid stroke="#1d2b3d" vertical={false} /><XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fill: "#68788d", fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} /><YAxis axisLine={false} tickLine={false} tick={{ fill: "#68788d", fontSize: 11 }} /><Tooltip contentStyle={{ background: "#111925", border: "1px solid #2a3b50", borderRadius: 12, color: "#fff" }} /><Legend iconType="circle" wrapperStyle={{ fontSize: 11, color: "#8d9aab" }} /><Line type="monotone" dataKey="critical" stroke="#ff647c" strokeWidth={2.5} dot={false} name="Critical" /><Line type="monotone" dataKey="high" stroke="#ff9f5b" strokeWidth={2.5} dot={false} name="High" /><Line type="monotone" dataKey="medium" stroke="#f5cf6b" strokeWidth={2.5} dot={false} name="Medium" /><Line type="monotone" dataKey="low" stroke="#55a6ff" strokeWidth={2.5} dot={false} name="Low" /></LineChart></ResponsiveContainer></div> : <EmptyState title="No trend data" description="Trend data will appear after the first scan." />}</section>
        <section className="panel rounded-2xl p-5 sm:p-6"><div className="eyebrow mb-2">Triage queue</div><h3 className="text-lg font-semibold text-white">Risk distribution</h3><p className="mt-1 text-sm text-slate-500">Where to focus your next remediation cycle.</p><div className="my-8 flex h-3 overflow-hidden rounded-full bg-slate-800">{risk.map((item) => <div key={item.label} style={{ width: item.width, backgroundColor: item.color }} />)}</div><div className="space-y-4">{risk.map((item) => <div key={item.label} className="flex items-center gap-3"><span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} /><span className="flex-1 text-sm text-slate-300">{item.label}</span><span className="font-mono text-sm text-white">{item.count}</span><span className="w-10 text-right text-xs text-slate-600">{Math.round((item.count / riskTotal) * 100)}%</span></div>)}</div><Link href="/scans" className="mt-8 flex items-center justify-between rounded-xl border border-slate-700/80 bg-slate-800/40 px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan-400/30 hover:text-cyan-200">Open scan history <ArrowRight className="h-4 w-4" /></Link></section>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.9fr_1.6fr]">
        <section className="panel rounded-2xl p-5 sm:p-6"><div className="mb-5 flex items-center justify-between"><div><div className="eyebrow mb-2">Latest activity</div><h3 className="text-lg font-semibold text-white">Recent scans</h3></div><Link href="/scans" className="text-xs font-medium text-cyan-300 hover:text-cyan-200">View all <ChevronRight className="inline h-3.5 w-3.5" /></Link></div><div className="space-y-2">{scans.slice(0, 5).map((scan) => <Link href="/scans" key={scan.scan_id} className="group flex items-center gap-3 rounded-xl border border-transparent p-2 transition hover:border-slate-700 hover:bg-slate-800/60"><span className={`flex h-8 w-8 items-center justify-center rounded-lg ${scan.status === "completed" ? "bg-emerald-400/10 text-emerald-300" : "bg-amber-400/10 text-amber-300"}`}>{scan.status === "completed" ? <CheckCircle2 className="h-4 w-4" /> : <Clock3 className="h-4 w-4" />}</span><span className="min-w-0 flex-1"><span className="block truncate text-sm text-slate-200">{scan.image_name}</span><span className="text-xs text-slate-600">{new Date(scan.completed_at || scan.started_at).toLocaleString()}</span></span><span className="text-right"><span className="block text-sm font-semibold text-slate-300">{scan.findings}</span><span className="text-[10px] uppercase tracking-wider text-slate-600">findings</span></span></Link>)}{!scans.length && <EmptyState title="No scans yet" description="Run a scan to start building history." />}</div></section>
        <section className="panel overflow-hidden rounded-2xl"><div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-5 sm:px-6"><div><div className="eyebrow mb-2">Inventory</div><h3 className="text-lg font-semibold text-white">Tracked images</h3></div><span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs text-slate-500">{images.length} total</span></div><div className="divide-y divide-slate-800/70">{images.slice(0, 5).map((img) => <Link href={`/images/${img.id}`} key={img.id} className="group flex items-center gap-4 px-5 py-4 transition hover:bg-slate-800/40 sm:px-6"><div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-700 bg-slate-800/80 text-cyan-300"><Package className="h-4 w-4" /></div><div className="min-w-0 flex-1"><div className="truncate font-mono text-sm text-slate-200">{img.registry === "dockerhub" ? "docker.io/" : `${img.registry}/`}{img.repo_name}:{img.tag}</div><div className="mt-1 flex items-center gap-2 text-xs text-slate-600"><span>Last scanned {img.last_scan_at ? new Date(img.last_scan_at).toLocaleDateString() : "never"}</span>{img.critical_count > 0 && <span className="text-rose-300">· {img.critical_count} critical</span>}</div></div><div className="text-right"><div className={`text-lg font-semibold ${img.open_findings > 10 ? "text-rose-300" : img.open_findings > 5 ? "text-orange-300" : "text-slate-200"}`}>{img.open_findings}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">open</div></div><ChevronRight className="h-4 w-4 text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-cyan-300" /></Link>)}{!images.length && <EmptyState title="No images tracked" description="Your inventory will appear here after scanning." />}</div></section>
      </div>
    </Layout>
  );
}
