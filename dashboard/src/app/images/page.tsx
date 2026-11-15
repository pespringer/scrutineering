"use client";

import Link from "next/link";
import { Package, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import type { ImageDetail, Page } from "@/types";

export default function ImagesPage() {
  const [page, setPage] = useState<Page<ImageDetail> | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/images?limit=100", { cache: "no-store" });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      setPage(Array.isArray(payload) ? { items: payload, limit: payload.length, offset: 0, count: payload.length, total: payload.length } : payload);
    } catch {
      setPage(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  if (loading && !page) return <Layout><LoadingSpinner /></Layout>;

  return <Layout>
    <div className="mb-8 flex items-end justify-between gap-4">
      <div><div className="eyebrow mb-3">Inventory / Managed images</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Images</h1><p className="mt-2 text-sm leading-6 text-slate-400">Open an image to review its current findings, resolved history, and remediation options.</p></div>
      <button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button>
    </div>
    <section className="panel overflow-hidden rounded-2xl">
      <div className="border-b border-slate-800/80 px-5 py-5 sm:px-6"><div className="eyebrow mb-2">Tracked inventory</div><div className="text-sm text-slate-400">{page?.total || 0} image{page?.total === 1 ? "" : "s"} currently under management.</div></div>
      <div className="divide-y divide-slate-800/70">{page?.items.map((image) => <Link href={`/images/${image.id}`} key={image.id} className="flex flex-col gap-4 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:px-6"><div className="flex min-w-0 flex-1 items-center gap-4"><div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><Package className="h-5 w-5" /></div><div className="min-w-0"><div className="truncate font-mono text-sm text-slate-200">{image.registry === "dockerhub" ? "docker.io/" : `${image.registry}/`}{image.repo_name}:{image.tag}</div><div className="mt-1 text-xs text-slate-600">Last scanned {image.last_scan_at ? new Date(image.last_scan_at).toLocaleString() : "never"}</div></div></div><div className="flex items-center gap-5 text-right"><div><div className="text-lg font-semibold text-slate-200">{image.open_findings}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">open</div></div><div><div className="text-lg font-semibold text-emerald-300">{image.resolved_findings || 0}</div><div className="text-[10px] uppercase tracking-wider text-slate-600">resolved</div></div></div></Link>)}{!page?.items.length && <EmptyState icon={Package} title="No images tracked" description="Run a scan to populate the managed image inventory." />}</div>
    </section>
  </Layout>;
}
