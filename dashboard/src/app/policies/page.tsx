"use client";

import { FormEvent, useEffect, useState } from "react";
import { CheckCircle2, CircleAlert, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Policy = { id: number; name: string; description?: string | null; policy_type: string; action: string; enabled: boolean; priority: number; rules: Record<string, number | string[]>; evaluation_count: number };

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [canManage, setCanManage] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [name, setName] = useState("Production severity gate");
  const [maxCritical, setMaxCritical] = useState("0");
  const [maxHigh, setMaxHigh] = useState("5");
  const [action, setAction] = useState("block");

  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/policies?include_disabled=true", { cache: "no-store" });
      if (!response.ok) throw new Error();
      setPolicies((await response.json()).items || []);
    } catch { setNotice("Policy data is unavailable."); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); fetch("/api/permissions", { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then((value) => setCanManage(Boolean(value?.can_manage_policies))).catch(() => undefined); }, []);

  async function createPolicy(event: FormEvent) {
    event.preventDefault();
    const response = await fetch("/api/policies", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, policy_type: "severity_threshold", action, rules: { max_critical: Number(maxCritical), max_high: Number(maxHigh) }, image_filters: {} }) });
    if (!response.ok) { setNotice("Unable to create policy. Check the thresholds."); return; }
    setNotice("Policy created and will evaluate on the next completed scan.");
    await load();
  }

  async function toggle(policy: Policy) {
    const response = await fetch(`/api/policies/${policy.id}/toggle`, { method: "POST" });
    if (response.ok) { setNotice(`${policy.name} ${policy.enabled ? "paused" : "enabled"}.`); await load(); }
  }

  if (loading && !policies.length) return <Layout><LoadingSpinner /></Layout>;
  return <Layout>
    <div className="mb-8 flex items-end justify-between gap-4"><div><div className="eyebrow mb-3">Governance / Policy engine</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Security policies</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Set bounded, auditable gates for image risk and review the evaluations produced by completed scans.</p></div><button onClick={load} aria-label="Refresh policies" className="rounded-xl border border-slate-700 bg-slate-900/80 p-3 text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /></button></div>
    {canManage && <form onSubmit={createPolicy} className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="mb-4 flex items-center gap-2"><Plus className="h-4 w-4 text-cyan-300" /><div><div className="eyebrow">New severity policy</div><h2 className="text-lg font-semibold text-white">Create a scan gate</h2></div></div><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><input value={name} onChange={(event) => setName(event.target.value)} required minLength={3} placeholder="Policy name" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-cyan-400/50" /><input type="number" min="0" value={maxCritical} onChange={(event) => setMaxCritical(event.target.value)} aria-label="Maximum critical findings" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200" /><input type="number" min="0" value={maxHigh} onChange={(event) => setMaxHigh(event.target.value)} aria-label="Maximum high findings" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200" /><select value={action} onChange={(event) => setAction(event.target.value)} className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200"><option value="block">Block</option><option value="alert">Alert</option><option value="require_approval">Require approval</option></select></div><div className="mt-3 flex items-center justify-between gap-3"><p className="text-xs text-slate-500">Critical and high thresholds are evaluated against every completed scan.</p><button className="rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300">Create policy</button></div></form>}
    {!canManage && <div className="panel mb-6 rounded-2xl p-5 text-sm text-slate-400">Your role can review policy outcomes but cannot change policy configuration.</div>}
    {notice && <p className="mb-4 text-sm text-cyan-200">{notice}</p>}
    <section className="space-y-3">{policies.map((policy) => <article key={policy.id} className="panel flex flex-col gap-4 rounded-2xl p-5 sm:flex-row sm:items-center sm:justify-between"><div className="flex items-start gap-3"><div className={`mt-1 rounded-lg p-2 ${policy.enabled ? "bg-emerald-400/10 text-emerald-300" : "bg-slate-800 text-slate-500"}`}>{policy.enabled ? <CheckCircle2 className="h-4 w-4" /> : <CircleAlert className="h-4 w-4" />}</div><div><h2 className="font-semibold text-white">{policy.name}</h2><p className="mt-1 text-xs text-slate-500">{policy.policy_type.replaceAll("_", " ")} · action: {policy.action} · {policy.evaluation_count} evaluations</p><p className="mt-2 text-sm text-slate-300">Max critical: {policy.rules.max_critical ?? "—"} · max high: {policy.rules.max_high ?? "—"}</p></div></div>{canManage && <button onClick={() => toggle(policy)} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-cyan-400/40 hover:text-white"><ShieldCheck className="h-4 w-4" />{policy.enabled ? "Pause" : "Enable"}</button>}</article>)}{!policies.length && <div className="panel rounded-2xl p-8 text-center text-sm text-slate-500">No policies configured yet.</div>}</section>
  </Layout>;
}
