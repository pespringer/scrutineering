"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, Check, Download, Filter, RefreshCw, Search, ShieldAlert, UserRound, Wand2 } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import SeverityBadge from "@/components/SeverityBadge";
import type { Page, VulnerabilityFinding } from "@/types";

const PAGE_SIZE = 25;
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function FindingsPage() {
  const [page, setPage] = useState<Page<VulnerabilityFinding> | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [lifecycle, setLifecycle] = useState("open");
  const [fixable, setFixable] = useState("");
  const [acknowledged, setAcknowledged] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<number[]>([]);
  const [assignee, setAssignee] = useState("");
  const [suppressionReason, setSuppressionReason] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const query = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset), lifecycle });
    if (search.trim()) query.set("search", search.trim());
    if (severity) query.set("severity", severity);
    if (fixable) query.set("fix_available", fixable);
    if (acknowledged) query.set("acknowledged", acknowledged);
    try {
      const response = await fetch(`/api/findings?${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error();
      setPage(await response.json());
    } catch { setPage({ items: [], limit: PAGE_SIZE, offset, count: 0, total: 0 }); setNotice("The findings service is unavailable."); }
    finally { setLoading(false); }
  }, [acknowledged, fixable, lifecycle, offset, search, severity]);

  useEffect(() => { load(); }, [load]);

  async function acknowledge() {
    if (!selected.length) return;
    setBusy(true); setNotice(null);
    const response = await fetch("/api/findings/bulk-acknowledge", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ids: selected }) });
    setNotice(response.ok ? `${selected.length} finding(s) acknowledged.` : "Unable to acknowledge the selected findings.");
    if (response.ok) { setSelected([]); await load(); }
    setBusy(false);
  }

  async function assignSelected() {
    if (!selected.length || !assignee.trim()) { setNotice("Enter an assignee before assigning findings."); return; }
    setBusy(true); setNotice(null);
    const response = await fetch("/api/findings/bulk-assign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ finding_ids: selected, assignee: assignee.trim() }) });
    setNotice(response.ok ? `${selected.length} finding(s) assigned to ${assignee.trim()}.` : "Unable to assign the selected findings.");
    if (response.ok) { setSelected([]); setAssignee(""); await load(); }
    setBusy(false);
  }

  async function suppressSelected() {
    if (!selected.length || !suppressionReason.trim()) { setNotice("Enter a reason before suppressing findings."); return; }
    setBusy(true); setNotice(null);
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const response = await fetch("/api/findings/suppress", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ finding_ids: selected, reason: suppressionReason.trim(), expires_at: expires }) });
    setNotice(response.ok ? `${selected.length} finding(s) suppressed for 30 days.` : "Unable to suppress the selected findings.");
    if (response.ok) { setSelected([]); setSuppressionReason(""); await load(); }
    setBusy(false);
  }

  async function proposeFix() {
    const selectedFindings = items.filter((finding) => selected.includes(finding.id) && finding.fix_available);
    const imageIds = [...new Set(selectedFindings.map((finding) => finding.image_id).filter((value): value is number => value !== undefined))];
    if (!selectedFindings.length) { setNotice("Select at least one finding with an available fix."); return; }
    if (imageIds.length !== 1) { setNotice("Select fixable findings from one image to create a remediation proposal."); return; }
    setBusy(true); setNotice(null);
    const response = await fetch("/api/remediations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_id: imageIds[0], finding_ids: selectedFindings.map((finding) => finding.id) }) });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) { setNotice(payload.detail || "Unable to create a remediation proposal."); setBusy(false); return; }
    window.location.assign(`/remediations/${payload.id}`);
  }

  function toggle(id: number, checked: boolean) { setSelected((current) => checked ? [...new Set([...current, id])] : current.filter((value) => value !== id)); }
  function updateFilter(setter: (value: string) => void, value: string) { setter(value); setOffset(0); setSelected([]); }
  const items = page?.items || [];
  const allSelected = items.length > 0 && items.every((finding) => selected.includes(finding.id));

  if (loading && !page) return <Layout><LoadingSpinner /></Layout>;
  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Workspace / Investigation</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Findings queue</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">One triage queue across every tracked image. Filter the exposure that needs a decision, then jump directly to the affected image or remediation.</p></div><button onClick={load} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" />Refresh</button></div>
    <section className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="flex flex-col gap-3 xl:flex-row xl:items-center"><div className="relative min-w-0 flex-1"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={search} onChange={(event) => updateFilter(setSearch, event.target.value)} placeholder="Search CVE, package, title, or image" className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" /></div><div className="flex flex-wrap gap-2"><select value={lifecycle} onChange={(event) => updateFilter(setLifecycle, event.target.value)} aria-label="Filter lifecycle" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-3 text-sm text-slate-300"><option value="open">Open</option><option value="resolved">Resolved</option><option value="all">All lifecycle</option></select><select value={severity} onChange={(event) => updateFilter(setSeverity, event.target.value)} aria-label="Filter severity" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-3 text-sm text-slate-300">{SEVERITIES.map((value) => <option key={value} value={value}>{value || "All severities"}</option>)}</select><select value={fixable} onChange={(event) => updateFilter(setFixable, event.target.value)} aria-label="Filter fix availability" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-3 text-sm text-slate-300"><option value="">All fixes</option><option value="true">Fix available</option><option value="false">No known fix</option></select><select value={acknowledged} onChange={(event) => updateFilter(setAcknowledged, event.target.value)} aria-label="Filter acknowledgement" className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-3 text-sm text-slate-300"><option value="">All acknowledgement</option><option value="false">Needs review</option><option value="true">Acknowledged</option></select></div></div><div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-slate-500"><Filter className="h-3.5 w-3.5" />{page?.total || 0} matching finding(s){selected.length > 0 && <><span>·</span><span className="text-cyan-200">{selected.length} selected</span><button disabled={busy} onClick={proposeFix} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/20 px-2.5 py-1.5 text-cyan-200 disabled:opacity-50"><Wand2 className="h-3.5 w-3.5" />Propose fix</button><button disabled={busy} onClick={acknowledge} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/20 px-2.5 py-1.5 text-emerald-200 disabled:opacity-50"><Check className="h-3.5 w-3.5" />Acknowledge</button><div className="flex items-center gap-1"><UserRound className="h-3.5 w-3.5" /><input aria-label="Assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Assignee" className="w-28 rounded-lg border border-slate-700 bg-slate-950/60 px-2 py-1.5 text-xs text-slate-200" /><button disabled={busy} onClick={assignSelected} className="rounded-lg border border-blue-400/20 px-2.5 py-1.5 text-blue-200 disabled:opacity-50">Assign</button></div><div className="flex items-center gap-1"><input aria-label="Suppression reason" value={suppressionReason} onChange={(event) => setSuppressionReason(event.target.value)} placeholder="Suppression reason" className="w-40 rounded-lg border border-slate-700 bg-slate-950/60 px-2 py-1.5 text-xs text-slate-200" /><button disabled={busy} onClick={suppressSelected} className="rounded-lg border border-amber-400/20 px-2.5 py-1.5 text-amber-200 disabled:opacity-50">Suppress 30d</button></div></>}</div>{notice && <p className="mt-3 text-sm text-cyan-200">{notice}</p>}</section>
    <section className="panel overflow-hidden rounded-2xl"><div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4 sm:px-6"><label className="flex items-center gap-3 text-xs text-slate-500"><input type="checkbox" checked={allSelected} onChange={(event) => setSelected(event.target.checked ? items.map((finding) => finding.id) : [])} className="h-4 w-4 accent-cyan-400" />Select visible</label><a href={`/api/findings/export?limit=5000${severity ? `&severity=${severity}` : ""}`} className="inline-flex items-center gap-2 text-xs text-cyan-200 hover:text-white"><Download className="h-3.5 w-3.5" />Export open findings</a></div><div className="divide-y divide-slate-800/70">{items.map((finding) => <div key={finding.id} className="flex flex-col gap-3 p-5 transition hover:bg-slate-800/30 lg:flex-row lg:items-center"><input aria-label={`Select finding ${finding.cve_id || finding.id}`} type="checkbox" checked={selected.includes(finding.id)} onChange={(event) => toggle(finding.id, event.target.checked)} className="h-4 w-4 shrink-0 accent-cyan-400" /><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="font-mono text-sm text-slate-200">{finding.cve_id || finding.package_name}</span>{finding.acknowledged && <span className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-500">Acknowledged</span>}{finding.suppressed && <span className="rounded-full border border-amber-400/20 px-2 py-0.5 text-[10px] uppercase tracking-wider text-amber-200">Suppressed</span>}</div><p className="mt-2 truncate text-sm text-slate-300">{finding.title || `${finding.package_name} ${finding.package_version || ""}`}</p><p className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500"><span className="font-mono">{finding.package_name} {finding.package_version || ""}</span><span>{finding.fix_available ? `Fix: ${finding.fixed_version || "available"}` : "No known fix"}</span></p></div><div className="flex flex-wrap items-center gap-2 lg:justify-end"><Link href={`/images/${finding.image_id}`} className="max-w-[260px] truncate rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/30 hover:text-cyan-200">{finding.image_name || `Image ${finding.image_id}`}<ArrowRight className="ml-1 inline h-3.5 w-3.5" /></Link>{finding.fix_available && <Link href={`/images/${finding.image_id}`} className="rounded-lg bg-cyan-400/10 px-3 py-2 text-xs text-cyan-200 hover:bg-cyan-400/20">Review fix</Link>}</div></div>)}{!items.length && <div className="p-10 text-center"><ShieldAlert className="mx-auto h-8 w-8 text-slate-700" /><p className="mt-3 text-sm text-slate-400">No findings match this view.</p><p className="mt-1 text-xs text-slate-600">Try broadening the filters or run a scan to populate the queue.</p></div>}</div></section>
    <div className="mt-5 flex items-center justify-between text-xs text-slate-600"><span>Showing {items.length ? (page?.offset || 0) + 1 : 0}–{(page?.offset || 0) + items.length} of {page?.total || 0}</span><div className="flex gap-3"><button disabled={!page || offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} className="text-cyan-300 disabled:text-slate-700">Previous</button><button disabled={!page || offset + PAGE_SIZE >= (page.total || 0)} onClick={() => setOffset(offset + PAGE_SIZE)} className="text-cyan-300 disabled:text-slate-700">Next</button></div></div>
  </Layout>;
}
