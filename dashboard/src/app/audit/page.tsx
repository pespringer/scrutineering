"use client";

import { useEffect, useState } from "react";
import { ClipboardList, RefreshCw } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import type { Page } from "@/types";

type AuditRecord = { id: number; timestamp: string; event_type: string; entity_id: string | null; detail: Record<string, unknown>; actor: string | null; actor_kind: string | null };

export default function AuditPage() {
  const [page, setPage] = useState<Page<AuditRecord> | null>(null);
  const [loading, setLoading] = useState(true);
  const [actor, setActor] = useState("");
  const [eventType, setEventType] = useState("");
  const [offset, setOffset] = useState(0);
  const load = () => { setLoading(true); const query = new URLSearchParams({ limit: "25", offset: String(offset) }); if (actor.trim()) query.set("actor", actor.trim()); if (eventType.trim()) query.set("event_type", eventType.trim()); fetch(`/api/audit?${query}`, { cache: "no-store" }).then((r) => r.json()).then(setPage).catch(() => setPage(null)).finally(() => setLoading(false)); };
  useEffect(load, [offset, actor, eventType]);
  if (loading && !page) return <Layout><LoadingSpinner /></Layout>;
  return <Layout><div className="mb-8 flex items-end justify-between gap-4"><div><div className="eyebrow mb-3">Governance / Operator activity</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Audit trail</h1><p className="mt-2 text-sm leading-6 text-slate-400">Every dashboard control action is recorded with its actor and target.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /> Refresh</button></div><section className="panel mb-5 flex flex-col gap-3 rounded-2xl p-4 sm:flex-row"><input value={actor} onChange={(e) => { setActor(e.target.value); setOffset(0); }} placeholder="Filter actor" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 outline-none" /><input value={eventType} onChange={(e) => { setEventType(e.target.value); setOffset(0); }} placeholder="Filter event type" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 outline-none" /></section><section className="panel overflow-hidden rounded-2xl"><div className="divide-y divide-slate-800/70">{page?.items.map((record) => <div key={record.id} className="flex flex-col gap-2 p-5 sm:flex-row sm:items-center sm:justify-between sm:px-6"><div className="flex items-center gap-3"><div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300"><ClipboardList className="h-4 w-4" /></div><div><div className="text-sm font-medium text-slate-200">{record.detail.action ? String(record.detail.action) : record.event_type}</div><div className="text-xs text-slate-600">{record.entity_id || "system"} · {record.actor || "unknown actor"}</div></div></div><time className="text-xs text-slate-500">{new Date(record.timestamp).toLocaleString()}</time></div>)}{!page?.items.length && <EmptyState icon={ClipboardList} title="No operator activity" description="Scan control actions will appear here." />}</div></section><div className="mt-4 flex items-center justify-between text-xs text-slate-600"><span>{page?.total || 0} total records</span><div className="flex gap-3"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 25))} className="text-cyan-300 disabled:text-slate-700">Previous</button><button disabled={offset + 25 >= (page?.total || 0)} onClick={() => setOffset(offset + 25)} className="text-cyan-300 disabled:text-slate-700">Next</button></div></div></Layout>;
}
