"use client";

import { useEffect, useState } from "react";
import { Activity, CheckCircle2, CircleAlert, Gauge, RefreshCw } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Operations = { panels: { key: string; title: string; metric: string; unit: string; threshold?: number }[]; scorecard: { status: string; checks: Record<string, boolean>; passed: number; total: number }; receiver_delivery: { enabled: boolean; deferred: boolean } };

export default function OperationsPage() {
  const [data, setData] = useState<Operations | null>(null);
  const [error, setError] = useState(false);
  const load = () => fetch("/api/production-operations", { cache: "no-store" }).then((response) => response.ok ? response.json() : Promise.reject()).then(setData).catch(() => setError(true));
  useEffect(() => { load(); }, []);
  if (!data && !error) return <Layout><LoadingSpinner /></Layout>;
  const scorecard = data?.scorecard;
  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Operations / Production maturity</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Operational readiness</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Receiver-independent health for scans, recovery, providers, backups, and release promotion.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" />Refresh</button></div>
    {error ? <div className="panel rounded-2xl p-6 text-sm text-rose-300">Operational telemetry is unavailable. Check the dashboard API connection.</div> : <>
      <section className={`mb-6 rounded-2xl border p-6 ${scorecard?.status === "ready" ? "border-emerald-400/20 bg-emerald-400/[.05]" : "border-amber-400/20 bg-amber-400/[.05]"}`}><div className="flex items-start justify-between gap-4"><div><div className="eyebrow mb-2">Promotion scorecard</div><h2 className="text-2xl font-semibold text-white">{scorecard?.status === "ready" ? "Ready for review" : "Attention required"}</h2><p className="mt-2 text-sm text-slate-400">{scorecard?.passed}/{scorecard?.total} receiver-independent checks passing.</p></div><Gauge className="h-8 w-8 text-cyan-300" /></div><div className="mt-5 grid gap-2 sm:grid-cols-5">{Object.entries(scorecard?.checks || {}).map(([key, passed]) => <div key={key} className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-950/30 px-3 py-2 text-xs text-slate-300">{passed ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-300" />}{key}</div>)}</div></section>
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{(data?.panels || []).map((panel) => <div key={panel.key} className="panel rounded-2xl p-5"><div className="mb-4 flex items-center justify-between"><div className="eyebrow">{panel.title}</div><Activity className="h-4 w-4 text-cyan-300" /></div><div className="font-mono text-xs text-slate-500">{panel.metric}</div><div className="mt-2 text-sm text-slate-300">Live {panel.unit} telemetry</div>{panel.threshold !== undefined && <div className="mt-3 text-xs text-slate-600">Target threshold: {panel.threshold} {panel.unit}</div>}</div>)}</section>
      <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/30 p-4 text-xs text-slate-500">External alert receiver delivery is disabled and remains a separate operator-gated validation track.</div>
    </>}
  </Layout>;
}
