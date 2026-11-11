"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { AlertOctagon, CheckCircle2, Clock3, Filter, Play, RefreshCw, Search, XCircle } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import type { Page, ScanResult } from "@/types";

const STATUS_FILTERS = ["all", "pending", "running", "completed", "failed"] as const;
const PAGE_SIZE = 20;

export default function ScansPage() {
  const [page, setPage] = useState<Page<ScanResult> | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<typeof STATUS_FILTERS[number]>("all");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [imageName, setImageName] = useState("");
  const [priority, setPriority] = useState("normal");
  const [starting, setStarting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    setLoading(true);
    try {
      const query = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
      if (filter !== "all") query.set("status", filter);
      if (search.trim()) query.set("search", search.trim());
      const response = await fetch(`/api/scans?${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      setPage(Array.isArray(payload) ? { items: payload, limit: payload.length, offset: 0, count: payload.length, total: payload.length } : payload);
    } catch { setPage(null); }
    finally { setLoading(false); }
  }, [filter, offset, search]);

  useEffect(() => { loadScans(); }, [loadScans]);

  useEffect(() => {
    if (!activeScanId) return;
    const timer = window.setInterval(async () => {
      const response = await fetch(`/api/scans/${activeScanId}`, { cache: "no-store" });
      if (!response.ok) return;
      const scan = await response.json() as ScanResult;
      if (["completed", "failed"].includes(scan.status)) {
        setActiveScanId(null); setNotice(`Scan ${scan.status}.`); loadScans();
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeScanId, loadScans]);

  async function startScan(event: FormEvent) {
    event.preventDefault();
    if (!imageName.trim()) return;
    setStarting(true); setNotice(null);
    try {
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_name: imageName.trim(), priority }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to queue scan");
      setImageName(""); setActiveScanId(payload.scan_id); setNotice(`Scan queued for ${payload.image_name}.`); setOffset(0); loadScans();
    } catch (error) { setNotice(error instanceof Error ? error.message : "Unable to queue scan."); }
    finally { setStarting(false); }
  }

  const scans = page?.items || [];
  const counts = {
    completed: scans.filter((s) => s.status === "completed").length,
    running: scans.filter((s) => s.status === "running" || s.status === "pending").length,
    failed: scans.filter((s) => s.status === "failed").length,
  };

  if (loading && !page) return <Layout><LoadingSpinner /></Layout>;

  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Operations / Scan history</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Scan history</h1><p className="mt-2 text-sm leading-6 text-slate-400">Review every scan and launch a targeted image check without leaving the control plane.</p></div><button onClick={loadScans} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button></div>
    <form onSubmit={startScan} className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="mb-4"><div className="eyebrow mb-2">Scan control</div><h2 className="text-lg font-semibold text-white">Run a targeted scan</h2></div><div className="flex flex-col gap-3 lg:flex-row"><div className="relative min-w-0 flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={imageName} onChange={(e) => setImageName(e.target.value)} placeholder="nginx:1.27 or ghcr.io/acme/api:v2" className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" /></div><select value={priority} onChange={(e) => setPriority(e.target.value)} className="rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 text-sm text-slate-300 outline-none"><option value="low">Low priority</option><option value="normal">Normal priority</option><option value="high">High priority</option></select><button disabled={starting || !imageName.trim()} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"><Play className="h-4 w-4" />{starting ? "Queueing…" : "Start scan"}</button></div>{notice && <p className="mt-3 text-sm text-cyan-200">{notice}</p>}</form>
    <div className="mb-6 grid grid-cols-3 gap-3"><MiniStat label="Completed" value={counts.completed} color="text-emerald-300" /><MiniStat label="In flight" value={counts.running} color="text-cyan-300" /><MiniStat label="Failed" value={counts.failed} color="text-rose-300" /></div>
    <section className="panel overflow-hidden rounded-2xl"><div className="flex flex-col gap-4 border-b border-slate-800/80 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6"><div className="relative w-full sm:max-w-sm"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} placeholder="Search images or repositories" className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-2.5 pl-10 pr-4 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" /></div><div className="flex items-center gap-2 overflow-x-auto"><Filter className="h-4 w-4 shrink-0 text-slate-600" />{STATUS_FILTERS.map((status) => <button type="button" key={status} onClick={() => { setFilter(status); setOffset(0); }} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-medium capitalize transition ${filter === status ? "bg-cyan-400/10 text-cyan-200 ring-1 ring-inset ring-cyan-300/20" : "text-slate-500 hover:bg-slate-800 hover:text-slate-200"}`}>{status}</button>)}</div></div><div className="divide-y divide-slate-800/70">{scans.map((scan) => <ScanRow key={scan.scan_id} scan={scan} />)}</div>{!scans.length && <EmptyState icon={Search} title="No matching scans" description={search ? "Try a different repository or clear the search." : "No scan history exists for this filter."} />}</section>
    <div className="mt-5 flex items-center justify-between text-xs text-slate-600"><span>Showing {page?.offset || 0}–{Math.min((page?.offset || 0) + scans.length, page?.total || 0)} of {page?.total || 0} scans</span><div className="flex gap-3"><button disabled={!page || (page.offset || 0) === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} className="text-cyan-300 disabled:text-slate-700">Previous</button><button disabled={!page || offset + PAGE_SIZE >= (page.total || 0)} onClick={() => setOffset(offset + PAGE_SIZE)} className="text-cyan-300 disabled:text-slate-700">Next</button></div></div>
  </Layout>;
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) { return <div className="panel rounded-2xl p-4 sm:p-5"><div className="eyebrow mb-3">{label}</div><div className={`text-2xl font-semibold ${color}`}>{value}</div></div>; }

function ScanRow({ scan }: { scan: ScanResult }) {
  const completed = scan.status === "completed";
  const failed = scan.status === "failed";
  const active = scan.status === "pending" || scan.status === "running";
  const duration = scan.completed_at ? Math.max(1, Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 60000)) : null;
  const Icon = completed ? CheckCircle2 : failed ? XCircle : active ? Clock3 : AlertOctagon;
  return <div className="group flex flex-col gap-4 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:px-6"><div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${completed ? "bg-emerald-400/10 text-emerald-300" : failed ? "bg-rose-400/10 text-rose-300" : "bg-cyan-400/10 text-cyan-300"}`}><Icon className="h-5 w-5" /></div><div className="min-w-0 flex-1"><div className="mb-1 flex flex-wrap items-center gap-2"><span className="truncate font-mono text-sm text-slate-200">{scan.image_name}</span><span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${completed ? "bg-emerald-400/10 text-emerald-300" : failed ? "bg-rose-400/10 text-rose-300" : "bg-cyan-400/10 text-cyan-300"}`}>{scan.status}</span></div><div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-600"><span>{scan.scan_id}</span><span className="hidden text-slate-700 sm:inline">·</span><span><Clock3 className="mr-1 inline h-3 w-3" />{new Date(scan.started_at).toLocaleString()}</span>{duration && <><span className="hidden text-slate-700 sm:inline">·</span><span>{duration} min runtime</span></>}</div></div><div className="flex items-center gap-4 pl-14 sm:pl-0"><div className="text-right"><div className="text-lg font-semibold text-slate-200">{scan.findings}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">findings</div></div><div className="hidden items-center gap-1.5 text-xs sm:flex"><span className="text-rose-300">{scan.critical_count}C</span><span className="text-orange-300">{scan.high_count}H</span><span className="text-yellow-300">{scan.medium_count}M</span><span className="text-blue-300">{scan.low_count}L</span></div></div></div>;
}
