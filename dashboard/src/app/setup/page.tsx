"use client";

import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, CircleAlert, Clock3, Play, RefreshCw, Search } from "lucide-react";
import Link from "next/link";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Step = { key: string; title: string; status: string; message: string; action: string };
type Registry = { registry: string; configured: boolean; required_keys: string[]; missing_keys: string[]; message: string };
type Onboarding = { status: string; completed: number; required: number; steps: Step[]; registries: Registry[] };
type Source = { id: number; display_name: string; status: string; enabled: boolean; last_reference?: string | null };
type FirstScan = { scan_id: string; image_name: string; status: string; findings?: number; error_message?: string | null };

export default function SetupPage() {
  const [data, setData] = useState<Onboarding | null>(null);
  const [error, setError] = useState(false);
  const [sources, setSources] = useState<Source[]>([]);
  const [sourceId, setSourceId] = useState("");
  const [sourceReference, setSourceReference] = useState("");
  const [imageName, setImageName] = useState("");
  const [firstScan, setFirstScan] = useState<FirstScan | null>(null);
  const [starting, setStarting] = useState(false);
  const [canManageScans, setCanManageScans] = useState(false);
  const [scanNotice, setScanNotice] = useState<string | null>(null);
  const load = () => fetch("/api/onboarding", { cache: "no-store" }).then((response) => response.ok ? response.json() : Promise.reject()).then(setData).catch(() => setError(true));
  useEffect(() => { load(); }, []);
  useEffect(() => {
    fetch("/api/sources", { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then((payload) => setSources(payload?.items || [])).catch(() => setSources([]));
    fetch("/api/permissions", { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then((permissions) => setCanManageScans(Boolean(permissions?.can_manage_scans))).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (!firstScan || ["completed", "failed", "cancelled"].includes(firstScan.status)) return;
    const timer = window.setInterval(async () => {
      const response = await fetch(`/api/scans/${firstScan.scan_id}`, { cache: "no-store" });
      if (!response.ok) return;
      const scan = await response.json();
      setFirstScan((current) => current ? { ...current, ...scan } : current);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [firstScan]);
  async function startFirstScan() {
    if (!imageName.trim() && (!sourceId || !sourceReference.trim())) return;
    setStarting(true); setScanNotice(null);
    try {
      const request = sourceId ? { source_id: Number(sourceId), image_reference: sourceReference.trim(), priority: "normal" } : { image_name: imageName.trim(), priority: "normal" };
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to queue scan");
      setFirstScan({ scan_id: payload.scan_id, image_name: payload.image_name, status: payload.status });
      setScanNotice("Scan queued. This page will update as the worker processes it.");
    } catch (scanError) { setScanNotice(scanError instanceof Error ? scanError.message : "Unable to queue scan."); }
    finally { setStarting(false); }
  }
  if (!data && !error) return <Layout><LoadingSpinner /></Layout>;
  const completion = data ? Math.round((data.completed / Math.max(1, data.required)) * 100) : 0;
  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Workspace / Setup</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Get to your first useful scan.</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Scrutineering gathers what it can automatically and tells you exactly what remains before the control room is useful.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" />Refresh checks</button></div>
    {error ? <div className="panel rounded-2xl p-6 text-sm text-rose-300">Setup diagnostics are unavailable. Check the dashboard API connection.</div> : <>
      <section className={`mb-6 rounded-2xl border p-6 ${data?.status === "ready" ? "border-emerald-400/20 bg-emerald-400/[.05]" : "border-amber-400/20 bg-amber-400/[.05]"}`}><div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="eyebrow mb-2">Readiness</div><h2 className="text-2xl font-semibold text-white">{data?.status === "ready" ? "Workspace ready" : "A few actions remain"}</h2><p className="mt-2 text-sm text-slate-400">{data?.completed}/{data?.required} required checks are complete. Deferred integrations are shown separately.</p></div><div className="text-right text-3xl font-semibold text-cyan-200">{completion}%</div></div><div className="mt-5 h-2 overflow-hidden rounded-full bg-slate-900"><div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400" style={{ width: `${completion}%` }} /></div></section>
      <section className="panel mb-6 rounded-2xl border-cyan-400/20 bg-cyan-400/[.03] p-5 sm:p-6"><div className="mb-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div><div className="eyebrow mb-2">First useful action</div><h2 className="text-xl font-semibold text-white">Run your first scan</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Start with a public image, or choose a verified private source. Results will appear here while the worker runs, then open directly in the investigation view.</p></div><Link href="/scans" className="inline-flex items-center gap-2 text-xs text-cyan-200 hover:text-white">Full scan history <ArrowRight className="h-3.5 w-3.5" /></Link></div>{canManageScans ? <div className="grid gap-3 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1fr)_auto]"><select value={sourceId} onChange={(event) => { setSourceId(event.target.value); setImageName(""); }} className="rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 text-sm text-slate-300 outline-none"><option value="">Public image reference</option>{sources.map((source) => <option key={source.id} value={source.id} disabled={!source.enabled || source.status !== "ready"}>{source.display_name} · {source.status}</option>)}</select>{sourceId ? <input value={sourceReference} onChange={(event) => setSourceReference(event.target.value)} placeholder={sources.find((source) => String(source.id) === sourceId)?.last_reference || "ghcr.io/acme/api:v2"} className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" /> : <div className="relative min-w-0"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={imageName} onChange={(event) => setImageName(event.target.value)} placeholder="nginx:1.27 or ghcr.io/acme/api:v2" className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" /></div>}<button onClick={startFirstScan} disabled={starting || (!imageName.trim() && (!sourceId || !sourceReference.trim()))} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"><Play className="h-4 w-4" />{starting ? "Queueing…" : "Start scan"}</button></div> : <p className="text-sm text-amber-200">Your role can review setup, but cannot start scans. Ask an operator or security operator to run the first scan.</p>}{scanNotice && <p className="mt-3 text-sm text-cyan-200">{scanNotice}</p>}{firstScan && <div className="mt-4 flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/40 p-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-sm text-slate-200">{firstScan.image_name}</span><span className="rounded-full border border-cyan-400/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-cyan-200">{firstScan.status}</span></div><p className="mt-1 text-xs text-slate-500">Scan ID {firstScan.scan_id}{firstScan.findings !== undefined ? ` · ${firstScan.findings} findings` : ""}{firstScan.error_message ? ` · ${firstScan.error_message}` : ""}</p></div>{["completed", "failed", "cancelled"].includes(firstScan.status) && <Link href={`/scans/${firstScan.scan_id}`} className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/20 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-400/10">Review result <ArrowRight className="h-3.5 w-3.5" /></Link>}</div>}</section>
      <section className="grid gap-3">{(data?.steps || []).map((step, index) => <div key={step.key} className="panel flex flex-col gap-4 rounded-2xl p-5 sm:flex-row sm:items-start"><div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${step.status === "ready" ? "bg-emerald-400/10 text-emerald-300" : step.status === "deferred" ? "bg-slate-700/40 text-slate-400" : "bg-amber-400/10 text-amber-200"}`}>{step.status === "ready" ? <CheckCircle2 className="h-5 w-5" /> : step.status === "deferred" ? <Clock3 className="h-5 w-5" /> : <CircleAlert className="h-5 w-5" />}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-xs font-mono text-slate-600">{String(index + 1).padStart(2, "0")}</span><h3 className="font-medium text-white">{step.title}</h3><span className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-500">{step.status.replace("_", " ")}</span></div><p className="mt-2 text-sm text-slate-300">{step.message}</p><p className="mt-2 text-xs leading-5 text-slate-500">Next: {step.action}</p></div>{step.key === "source" && <div className="flex flex-wrap gap-2"><Link href="/scans" className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/20 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-400/10">Open scans <ArrowRight className="h-3.5 w-3.5" /></Link><Link href="/sources" className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:text-white">Manage sources <ArrowRight className="h-3.5 w-3.5" /></Link></div>}{(step.key === "backup" || step.key === "restore") && <Link href="/operations" className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/20 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-400/10">Open operations <ArrowRight className="h-3.5 w-3.5" /></Link>}</div>)}</section>
      <section className="mt-6 panel rounded-2xl p-5 sm:p-6"><div className="mb-4"><div className="eyebrow mb-2">Image sources</div><h2 className="text-xl font-semibold text-white">Registry readiness</h2><p className="mt-1 text-sm text-slate-400">Credentials are detected from the running service configuration; secret values are never returned.</p></div><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{(data?.registries || []).map((registry) => <div key={registry.registry} className="rounded-xl border border-slate-800 bg-slate-950/30 p-4"><div className="flex items-center justify-between gap-3"><span className="font-mono text-sm text-slate-200">{registry.registry}</span>{registry.configured ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-200" />}</div><p className="mt-2 text-xs leading-5 text-slate-500">{registry.configured ? "Credential configuration is present or anonymous access is supported." : registry.message}</p>{registry.missing_keys.length > 0 && <p className="mt-2 break-words font-mono text-[10px] text-amber-200">Missing: {registry.missing_keys.join(", ")}</p>}</div>)}</div></section>
    </>}
  </Layout>;
}
