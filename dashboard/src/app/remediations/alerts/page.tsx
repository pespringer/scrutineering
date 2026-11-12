"use client";

import { useEffect, useState } from "react";
import Layout from "@/components/Layout";

type Delivery = { id: number; publication_id: number; receiver: string; status: string; attempts: number; max_attempts: number; last_error?: string | null };

export default function AlertDeliveriesPage() {
  const [items, setItems] = useState<Delivery[]>([]);
  const [busy, setBusy] = useState<number | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  async function load() { const response = await fetch("/api/remediations/alert-deliveries?status=dead_letter", { cache: "no-store" }); if (response.ok) setItems((await response.json()).items || []); }
  useEffect(() => { void load(); }, []);
  async function replay(id: number) { setBusy(id); await fetch(`/api/remediations/alert-deliveries/${id}/replay`, { method: "POST" }); await load(); setBusy(null); }
  async function cancelSelected() { await fetch("/api/remediations/alert-deliveries/cancel", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ delivery_ids: selected }) }); setSelected([]); await load(); }
  return <Layout><div className="mb-8"><div className="eyebrow mb-3">Governance / Alert delivery</div><h1 className="text-3xl font-semibold tracking-tight text-white">Dead-lettered alerts</h1><p className="mt-2 text-sm text-slate-400">Review deterministic delivery failures and replay them after correcting the receiver configuration.</p></div><section className="panel overflow-hidden rounded-2xl"><div className="flex justify-end border-b border-slate-800 p-4"><button disabled={!selected.length} onClick={cancelSelected} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 disabled:opacity-40">Cancel selected ({selected.length})</button></div><div className="divide-y divide-slate-800/70">{items.map((item) => <div key={item.id} className="flex flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between"><div className="flex items-start gap-3"><input type="checkbox" checked={selected.includes(item.id)} onChange={() => setSelected((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} /><div><div className="font-medium text-slate-200">Delivery #{item.id} · {item.receiver}</div><div className="text-xs text-slate-500">Publication #{item.publication_id} · {item.attempts}/{item.max_attempts} attempts</div>{item.last_error ? <div className="mt-1 text-xs text-rose-300">{item.last_error}</div> : null}</div></div><button onClick={() => replay(item.id)} disabled={busy === item.id} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-200 disabled:opacity-50">{busy === item.id ? "Replaying…" : "Replay"}</button></div>)}{!items.length && <div className="p-8 text-sm text-slate-400">No dead-lettered alert deliveries.</div>}</div></section></Layout>;
}
