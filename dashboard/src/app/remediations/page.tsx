"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, RefreshCw } from "lucide-react";
import Link from "next/link";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";

type Remediation = { id: number; image_id: number; status: string; finding_count: number; stale_publication_count?: number; actions: Array<{ package_name?: string }> };

export default function RemediationsPage() {
  const [items, setItems] = useState<Remediation[] | null>(null);
  const [error, setError] = useState(false);
  const load = () => { setError(false); fetch("/api/remediations?limit=50", { cache: "no-store" }).then((response) => { if (!response.ok) throw new Error(); return response.json(); }).then((payload) => setItems(payload.items || [])).catch(() => { setItems([]); setError(true); }); };
  useEffect(load, []);
  if (items === null) return <Layout><LoadingSpinner /></Layout>;
  return <Layout><div className="mb-8 flex items-end justify-between gap-4"><div><div className="eyebrow mb-3">Governance / Remediation queue</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Remediation queue</h1><p className="mt-2 text-sm leading-6 text-slate-400">Review proposed fixes and approval state before any execution worker can mutate a repository.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button></div>{error ? <div className="panel rounded-2xl p-6 text-sm text-amber-200">Remediation visibility requires a remediator or security-operator role.</div> : <section className="panel overflow-hidden rounded-2xl"><div className="divide-y divide-slate-800/70">{items.map((item) => <Link href={`/remediations/${item.id}`} key={item.id} className="flex flex-col gap-3 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:justify-between sm:px-6"><div className="flex items-center gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-400/10 text-violet-300"><ShieldCheck className="h-5 w-5" /></div><div><div className="font-medium text-slate-200">Remediation #{item.id} · image {item.image_id}</div><div className="text-xs text-slate-500">{item.finding_count} finding(s) · {item.actions.length} proposed action(s)</div></div></div><div className="flex items-center gap-2">{item.stale_publication_count ? <span className="rounded-full bg-amber-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-amber-200">{item.stale_publication_count} stale</span> : null}<span className="rounded-full bg-violet-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-violet-200">{item.status}</span></div></Link>)}{!items.length && <EmptyState icon={ShieldCheck} title="No remediation proposals" description="Approved preview requests will appear here." />}</div></section>}</Layout>;
}
