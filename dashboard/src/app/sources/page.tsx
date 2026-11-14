"use client";

import { FormEvent, useEffect, useState } from "react";
import { ArrowLeft, CheckCircle2, CircleAlert, Link2, Plus, RefreshCw } from "lucide-react";
import Link from "next/link";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Source = { id: number; display_name: string; registry_host: string; credential_keys: string[]; status: string; last_reference?: string | null; last_digest?: string | null; last_error?: string | null; last_checked_at?: string | null };

export default function SourcesPage() {
  const [sources, setSources] = useState<Source[] | null>(null);
  const [references, setReferences] = useState<Record<number, string>>({});
  const [name, setName] = useState("");
  const [registry, setRegistry] = useState("ghcr.io");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => fetch("/api/sources", { cache: "no-store" }).then((response) => response.ok ? response.json() : Promise.reject()).then((payload) => setSources(payload.items || [])).catch(() => setSources([]));
  useEffect(() => { load(); }, []);
  const create = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setNotice("");
    try { const response = await fetch("/api/sources", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ display_name: name, registry_host: registry }) }); const body = await response.json(); if (!response.ok) throw new Error(body.detail || "Source creation failed"); setName(""); setNotice("Source added. Use a representative tagged image to validate it."); await load(); } catch (error) { setNotice(error instanceof Error ? error.message : "Source creation failed."); } finally { setBusy(false); }
  };
  const check = async (source: Source) => {
    const reference = references[source.id]?.trim();
    if (!reference) return;
    setBusy(true); setNotice("");
    try { const response = await fetch(`/api/sources/${source.id}/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_reference: reference }) }); const body = await response.json(); if (!response.ok) throw new Error(body.detail || "Source check failed"); setNotice(`Source verified at ${body.digest}.`); await load(); } catch (error) { setNotice(error instanceof Error ? error.message : "Source check failed."); await load(); } finally { setBusy(false); }
  };
  if (sources === null) return <Layout><LoadingSpinner /></Layout>;
  return <Layout><div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><Link href="/setup" className="mb-3 inline-flex items-center gap-2 text-xs text-cyan-300"><ArrowLeft className="h-3.5 w-3.5" />Setup</Link><div className="eyebrow mb-2">Workspace / Image sources</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Registry sources</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Connect a source once, validate it with a real tagged image, then use the same coordinates for repeatable scans.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" />Refresh</button></div>
    <form onSubmit={create} className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white"><Plus className="h-4 w-4 text-cyan-300" />Add a registry source</div><div className="flex flex-col gap-3 sm:flex-row"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Production GHCR" className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200 placeholder:text-slate-600" /><select value={registry} onChange={(event) => setRegistry(event.target.value)} className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200"><option value="dockerhub">Docker Hub</option><option value="ghcr.io">GitHub Container Registry</option><option value="gitlab">GitLab Registry</option><option value="ecr">Amazon ECR</option><option value="gcr.io">Google Container Registry</option></select><button disabled={busy || name.trim().length < 2} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 disabled:opacity-50"><Link2 className="h-4 w-4" />Add source</button></div>{notice && <p className="mt-3 text-sm text-cyan-200">{notice}</p>}</form>
    <section className="grid gap-3">{sources.map((source) => { const reference = references[source.id] ?? ""; return <div key={source.id} className="panel flex flex-col gap-4 rounded-2xl p-5"><div className="flex min-w-0 items-start gap-3"><div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${source.status === "ready" ? "bg-emerald-400/10 text-emerald-300" : source.status === "failed" ? "bg-rose-400/10 text-rose-300" : "bg-amber-400/10 text-amber-200"}`}>{source.status === "ready" ? <CheckCircle2 className="h-5 w-5" /> : <CircleAlert className="h-5 w-5" />}</div><div className="min-w-0"><h2 className="font-medium text-white">{source.display_name}</h2><p className="mt-1 font-mono text-xs text-slate-400">{source.registry_host} · {source.status}</p>{source.credential_keys.length > 0 && <p className="mt-2 break-words text-xs text-slate-600">Credentials detected by keys: {source.credential_keys.join(", ")}</p>}{source.last_digest && <p className="mt-2 truncate font-mono text-xs text-emerald-200">{source.last_digest}</p>}{source.last_error && <p className="mt-2 text-xs text-rose-300">{source.last_error}</p>}</div></div><div className="flex flex-col gap-2 sm:flex-row"><input aria-label={`Tagged image for ${source.display_name}`} value={reference} onChange={(event) => setReferences((current) => ({ ...current, [source.id]: event.target.value }))} placeholder={source.registry_host === "ghcr.io" ? "ghcr.io/OWNER/IMAGE:TAG" : `${source.registry_host}/repository/image:tag`} className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 font-mono text-xs text-slate-200 placeholder:text-slate-600" /><button onClick={() => check(source)} disabled={busy || !reference} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-cyan-400/20 px-4 py-2.5 text-sm text-cyan-200 disabled:opacity-50">Check with tagged image</button></div></div>; })}{!sources.length && <div className="panel rounded-2xl p-8 text-center text-sm text-slate-500">No durable sources yet. Add one above or start a targeted scan from Scan history.</div>}</section>
  </Layout>;
}
