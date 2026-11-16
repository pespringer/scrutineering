"use client";

import Link from "next/link";
import { AlertTriangle, CircleSlash2, Container, ExternalLink, Package, Play, RefreshCw, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import type { ImageDetail, Page, RegistryInventory, RegistryTag } from "@/types";

const statusCopy: Record<RegistryTag["security_status"], string> = { clean: "Clean", issues_found: "Issues found", scanning: "Scanning", scan_failed: "Scan failed", not_scanned: "Not scanned" };
function statusStyle(status: RegistryTag["security_status"]) { if (status === "clean") return "bg-emerald-400/10 text-emerald-200"; if (status === "issues_found" || status === "scan_failed") return "bg-rose-400/10 text-rose-200"; if (status === "scanning") return "bg-cyan-400/10 text-cyan-200"; return "bg-amber-400/10 text-amber-200"; }

export default function ImagesPage() {
  const [page, setPage] = useState<Page<ImageDetail> | null>(null);
  const [registry, setRegistry] = useState<RegistryInventory | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [imagesResponse, registryResponse] = await Promise.all([fetch("/api/images?limit=100", { cache: "no-store" }), fetch("/api/registry", { cache: "no-store" })]);
      if (!imagesResponse.ok) throw new Error();
      const payload = await imagesResponse.json();
      setPage(Array.isArray(payload) ? { items: payload, limit: payload.length, offset: 0, count: payload.length, total: payload.length } : payload);
      setRegistry(registryResponse.ok ? await registryResponse.json() : null);
    } catch { setPage(null); setRegistry(null); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function scanTag(item: RegistryTag) {
    setScanning(item.image_name); setNotice("");
    try {
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_name: item.image_name, priority: "normal" }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || body.error || "Unable to queue scan");
      setNotice(`Scan queued for ${item.image_name}. The security status will update when the worker finishes.`); await load();
    } catch (error) { setNotice(error instanceof Error ? error.message : "Unable to queue scan"); } finally { setScanning(null); }
  }

  if (loading && !page) return <Layout><LoadingSpinner /></Layout>;
  return <Layout>
    <div className="mb-8 flex items-end justify-between gap-4"><div><div className="eyebrow mb-3">Inventory / Registry control room</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Images</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">One place to see what is in the local registry, what Scrutineering has scanned, and which images need attention.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button></div>
    {notice && <div className="mb-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-sm text-cyan-100">{notice}</div>}
    {registry ? <>
      <section className="mb-6 rounded-3xl border border-cyan-400/15 bg-gradient-to-br from-[#101d2d] to-[#0c131e] p-5 shadow-2xl shadow-cyan-950/10 sm:p-7"><div className="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between"><div><div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300"><span className={`h-2 w-2 rounded-full ${registry.registry.reachable ? "bg-emerald-400" : "bg-rose-400"}`} /> Local registry {registry.registry.reachable ? "connected" : "unavailable"}</div><h2 className="text-2xl font-semibold text-white">{registry.registry.host}</h2><p className="mt-2 text-sm leading-6 text-slate-400">Tags are read directly from the registry and joined with scan findings, scan history, and remediation state.</p></div><div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><Summary label="Repositories" value={registry.summary.repositories} icon={<Container className="h-4 w-4" />} /><Summary label="Tags" value={registry.summary.tags} icon={<Package className="h-4 w-4" />} /><Summary label="Issues" value={registry.summary.issues_found} icon={<ShieldAlert className="h-4 w-4" />} /><Summary label="Unscanned" value={registry.summary.not_scanned} icon={<CircleSlash2 className="h-4 w-4" />} /></div></div></section>
      <section className="panel mb-8 overflow-hidden rounded-2xl"><div className="flex flex-col gap-2 border-b border-slate-800/80 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-6"><div><div className="eyebrow mb-2">Registry catalog</div><div className="text-sm text-slate-400">Every repository tag is actionable from this view.</div></div><a href={registry.registry.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 text-xs text-cyan-300 hover:text-cyan-200">Open registry API <ExternalLink className="h-3.5 w-3.5" /></a></div><div className="divide-y divide-slate-800/70">{registry.tags.map((item) => <div key={`${item.repository}:${item.tag}`} className="flex flex-col gap-4 p-5 transition hover:bg-slate-800/20 lg:flex-row lg:items-center lg:justify-between lg:px-6"><div className="flex min-w-0 items-center gap-4"><div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><Package className="h-5 w-5" /></div><div className="min-w-0"><div className="truncate font-mono text-sm text-slate-200">{item.repository}:{item.tag}</div><div className="mt-1 flex flex-wrap gap-3 text-xs text-slate-600"><span>{item.digest ? item.digest.slice(0, 19) : "digest unavailable"}</span><span>{item.last_scan_at ? `Scanned ${new Date(item.last_scan_at).toLocaleString()}` : "Never scanned"}</span></div></div></div><div className="flex flex-wrap items-center gap-3 lg:justify-end"><span className={`rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider ${statusStyle(item.security_status)}`}>{statusCopy[item.security_status]}</span>{item.open_findings > 0 && <span className="text-xs text-rose-200">{item.open_findings} open · {item.critical_count} critical · {item.high_count} high</span>}{item.image_id ? <Link href={`/images/${item.image_id}`} className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">Details <ExternalLink className="h-3.5 w-3.5" /></Link> : null}<button disabled={scanning === item.image_name || item.security_status === "scanning"} onClick={() => scanTag(item)} className="inline-flex items-center gap-1 rounded-lg border border-violet-400/30 px-3 py-2 text-xs text-violet-100 disabled:cursor-not-allowed disabled:opacity-40"><Play className="h-3.5 w-3.5" /> {item.security_status === "scanning" ? "Scanning" : item.image_id ? "Rescan" : "Scan image"}</button></div></div>)}{!registry.tags.length && <EmptyState icon={Package} title="Registry is empty" description="Push an image to localhost:5000, then refresh this page." />}</div></section>
    </> : <div className="mb-8 rounded-2xl border border-amber-400/20 bg-amber-400/5 p-5 text-sm text-amber-100"><div className="flex items-center gap-2 font-medium"><AlertTriangle className="h-4 w-4" /> Local registry unavailable</div><p className="mt-2 text-amber-200/70">Start the Compose registry service and refresh. Existing tracked scan results remain available below.</p></div>}
    <section className="panel overflow-hidden rounded-2xl"><div className="border-b border-slate-800/80 px-5 py-5 sm:px-6"><div className="eyebrow mb-2">Tracked inventory</div><div className="text-sm text-slate-400">{page?.total || 0} image{page?.total === 1 ? "" : "s"} currently under management.</div></div><div className="divide-y divide-slate-800/70">{page?.items.map((image) => { const localFixture = image.repo_name.startsWith("local/"); const displayName = `${localFixture ? "" : image.registry === "dockerhub" ? "docker.io/" : `${image.registry}/`}${image.repo_name}:${image.tag}`; return <Link href={`/images/${image.id}`} key={image.id} className="flex flex-col gap-4 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:px-6"><div className="flex min-w-0 flex-1 items-center gap-4"><div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><Package className="h-5 w-5" /></div><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><div className="truncate font-mono text-sm text-slate-200">{displayName}</div>{localFixture && <span className="rounded-full bg-violet-400/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-violet-200">local fixture</span>}</div><div className="mt-1 text-xs text-slate-600">Last scanned {image.last_scan_at ? new Date(image.last_scan_at).toLocaleString() : "never"}</div></div></div><div className="flex items-center gap-5 text-right"><div><div className="text-lg font-semibold text-slate-200">{image.open_findings}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">open</div></div><div><div className="text-lg font-semibold text-emerald-300">{image.resolved_findings || 0}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">resolved</div></div></div></Link>; })}{!page?.items.length && <EmptyState icon={Package} title="No images tracked" description="Run a scan to populate the managed image inventory." />}</div></section>
  </Layout>;
}

function Summary({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) { return <div className="rounded-2xl border border-slate-700/70 bg-slate-950/35 px-4 py-3"><div className="mb-2 flex items-center justify-between text-slate-500">{label}<span className="text-cyan-300">{icon}</span></div><div className="text-2xl font-semibold text-white">{value}</div></div>; }
