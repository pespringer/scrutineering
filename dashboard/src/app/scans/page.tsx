"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AlertOctagon, CheckCircle2, Clock3, Filter, RefreshCw, Search, XCircle } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import type { ScanResult } from "@/types";

const STATUS_FILTERS = ["all", "completed", "partial", "failed"] as const;

export default function ScansPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<typeof STATUS_FILTERS[number]>("all");
  const [search, setSearch] = useState("");

  const loadScans = () => {
    setLoading(true);
    fetch("/api/scans", { cache: "no-store" }).then((r) => { if (!r.ok) throw new Error(); return r.json(); }).then(setScans).catch(() => setScans([])).finally(() => setLoading(false));
  };
  useEffect(loadScans, []);

  const filtered = useMemo(() => scans.filter((scan) => {
    return (filter === "all" || scan.status === filter) && scan.image_name.toLowerCase().includes(search.toLowerCase());
  }), [filter, scans, search]);
  const counts = { completed: scans.filter((s) => s.status === "completed").length, partial: scans.filter((s) => s.status === "partial").length, failed: scans.filter((s) => s.status === "failed").length };

  if (loading) return <Layout><LoadingSpinner /></Layout>;

  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Operations / Scan history</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Scan history</h1><p className="mt-2 text-sm leading-6 text-slate-400">Review every scan, its outcome, and the exposure it discovered.</p></div><button onClick={loadScans} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button></div>
    <div className="mb-6 grid grid-cols-3 gap-3"><MiniStat label="Completed" value={counts.completed} color="text-emerald-300" /><MiniStat label="Partial" value={counts.partial} color="text-amber-300" /><MiniStat label="Failed" value={counts.failed} color="text-rose-300" /></div>
    <section className="panel overflow-hidden rounded-2xl"><div className="flex flex-col gap-4 border-b border-slate-800/80 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6"><div className="relative w-full sm:max-w-sm"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search images or repositories" className="w-full rounded-xl border border-slate-700 bg-slate-900/70 py-2.5 pl-10 pr-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/10" /></div><div className="flex items-center gap-2 overflow-x-auto"><Filter className="h-4 w-4 shrink-0 text-slate-600" />{STATUS_FILTERS.map((status) => <button key={status} onClick={() => setFilter(status)} className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-medium capitalize transition ${filter === status ? "bg-cyan-400/10 text-cyan-200 ring-1 ring-inset ring-cyan-300/20" : "text-slate-500 hover:bg-slate-800 hover:text-slate-200"}`}>{status}</button>)}</div></div><div className="divide-y divide-slate-800/70">{filtered.map((scan) => <ScanRow key={scan.scan_id} scan={scan} />)}</div>{!filtered.length && <EmptyState icon={Search} title="No matching scans" description={search ? "Try a different repository or clear the search." : "No scan history exists for this filter."} action={search ? <button onClick={() => setSearch("")} className="mt-3 text-sm font-medium text-cyan-300">Clear search</button> : undefined} />}</section>
    <div className="mt-5 flex items-center justify-between text-xs text-slate-600"><span>Showing {filtered.length} of {scans.length} scans</span>{filter !== "all" && <button onClick={() => setFilter("all")} className="text-cyan-300 hover:text-cyan-200">Clear filter</button>}</div>
  </Layout>;
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) { return <div className="panel rounded-2xl p-4 sm:p-5"><div className="eyebrow mb-3">{label}</div><div className={`text-2xl font-semibold ${color}`}>{value}</div></div>; }

function ScanRow({ scan }: { scan: ScanResult }) {
  const completed = scan.status === "completed";
  const failed = scan.status === "failed";
  const duration = scan.completed_at ? Math.max(1, Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 60000)) : null;
  const Icon = completed ? CheckCircle2 : failed ? XCircle : AlertOctagon;
  return <Link href="/scans" className="group flex flex-col gap-4 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:px-6"><div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${completed ? "bg-emerald-400/10 text-emerald-300" : failed ? "bg-rose-400/10 text-rose-300" : "bg-amber-400/10 text-amber-300"}`}><Icon className="h-5 w-5" /></div><div className="min-w-0 flex-1"><div className="mb-1 flex flex-wrap items-center gap-2"><span className="truncate font-mono text-sm text-slate-200">{scan.image_name}</span><span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${completed ? "bg-emerald-400/10 text-emerald-300" : failed ? "bg-rose-400/10 text-rose-300" : "bg-amber-400/10 text-amber-300"}`}>{scan.status}</span></div><div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-600"><span>{scan.scan_id}</span><span className="hidden text-slate-700 sm:inline">·</span><span><Clock3 className="mr-1 inline h-3 w-3" />{new Date(scan.started_at).toLocaleString()}</span>{duration && <><span className="hidden text-slate-700 sm:inline">·</span><span>{duration} min runtime</span></>}</div></div><div className="flex items-center gap-4 pl-14 sm:pl-0"><div className="text-right"><div className="text-lg font-semibold text-slate-200">{scan.findings}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">findings</div></div><div className="hidden items-center gap-1.5 text-xs sm:flex"><span className="text-rose-300">{scan.critical_count}C</span><span className="text-orange-300">{scan.high_count}H</span><span className="text-yellow-300">{scan.medium_count}M</span><span className="text-blue-300">{scan.low_count}L</span></div></div></Link>;
}
