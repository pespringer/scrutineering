"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, CircleAlert, RefreshCw } from "lucide-react";

type Check = { status: string; message: string; mode?: string };
type Health = { status: string; checks: Record<string, Check>; blocked_checks: string[] };

export default function ControlPlaneHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const load = () => {
    setLoading(true);
    fetch("/api/system/health", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then(setHealth)
      .catch(() => setHealth(null))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  return <section className={`mb-6 rounded-2xl border p-5 ${health?.status === "ready" ? "border-emerald-400/20 bg-emerald-400/[.05]" : "border-amber-400/20 bg-amber-400/[.05]"}`}>
    <div className="flex items-start justify-between gap-4">
      <div><div className="eyebrow mb-2">Control-plane health</div><h2 className="text-xl font-semibold text-white">{loading ? "Checking system…" : health?.status === "ready" ? "System ready" : "Action required"}</h2><p className="mt-1 text-sm text-slate-400">Live diagnostics for the services this dashboard depends on.</p></div>
      <button onClick={load} aria-label="Refresh control-plane health" className="rounded-lg border border-slate-700 p-2 text-slate-400 hover:text-white"><RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /></button>
    </div>
    <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">{Object.entries(health?.checks || {}).map(([name, check]) => <div key={name} className="rounded-xl border border-slate-800 bg-slate-950/30 p-3"><div className="flex items-center gap-2 text-xs font-medium capitalize text-slate-200">{check.status === "ready" || check.status === "optional" ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-300" />}{name.replaceAll("_", " ")}</div><p className="mt-2 text-xs leading-5 text-slate-500">{check.message}</p></div>)}</div>
    {!loading && !health ? <p className="mt-4 text-xs text-rose-300">Health diagnostics are unavailable. Check the API connection.</p> : null}
  </section>;
}
