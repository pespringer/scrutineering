"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ScanResult } from "@/types";
import { ArrowLeft, CheckCircle2, Clock3, ExternalLink, XCircle } from "lucide-react";
import { useParams } from "next/navigation";

export default function ScanDetailPage() {
  const params = useParams();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [findings, setFindings] = useState<Array<{ id: number; cve_id?: string; package_name: string; package_version?: string; fixed_version?: string; severity: string; title?: string; fix_available?: boolean }>>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => { Promise.all([fetch(`/api/scans/${params.id}`, { cache: "no-store" }), fetch(`/api/scans/${params.id}/findings`, { cache: "no-store" })]).then(async ([scanResponse, findingsResponse]) => { if (!scanResponse.ok) throw new Error(); setScan(await scanResponse.json()); if (findingsResponse.ok) setFindings((await findingsResponse.json()).items || []); }).catch(() => setScan(null)).finally(() => setLoading(false)); }, [params.id]);
  async function proposeFixes() {
    if (!scan || !scan.image_id || !findings.length) return;
    const fixable = findings.filter((finding) => finding.fix_available).map((finding) => finding.id);
    if (!fixable.length) { setNotice("No fixable findings are available in this scan."); return; }
    const response = await fetch("/api/remediations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ image_id: scan.image_id, finding_ids: fixable }) });
    setNotice(response.ok ? "Remediation proposal created. Review it in Remediations." : "Unable to create a remediation proposal.");
  }
  if (loading) return <Layout><LoadingSpinner /></Layout>;
  if (!scan) return <Layout><EmptyState title="Scan not found" description="The scan record is unavailable or has been removed." /></Layout>;
  const terminal = ["completed", "failed", "cancelled", "partial"].includes(scan.status);
  return <Layout><Link href="/scans" className="mb-6 inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300"><ArrowLeft className="h-4 w-4" /> Back to scans</Link><div className="panel rounded-2xl p-6"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start"><div><div className="eyebrow mb-2">Scan detail</div><h1 className="break-all font-mono text-2xl font-semibold text-white">{scan.image_name}</h1><p className="mt-2 text-xs text-slate-500">{scan.scan_id}</p></div><div className="flex items-center gap-3"><span className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-3 py-1.5 text-xs uppercase tracking-wider text-slate-300">{terminal ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <Clock3 className="h-4 w-4 text-cyan-300" />}{scan.status}</span>{findings.some((finding) => finding.fix_available) && <button onClick={proposeFixes} className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-300"><ExternalLink className="h-3.5 w-3.5" /> Propose fixes</button>}</div></div><div className="mt-8 grid gap-3 sm:grid-cols-4">{[["Findings", scan.findings], ["Critical", scan.critical_count], ["High", scan.high_count], ["Medium", scan.medium_count]].map(([label, value]) => <div key={label} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4"><div className="eyebrow">{label}</div><div className="mt-2 text-2xl font-semibold text-white">{value}</div></div>)}</div>{notice && <div className="mt-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-4 text-sm text-cyan-200">{notice}</div>}{scan.error_message && <div className="mt-5 rounded-xl border border-rose-400/20 bg-rose-400/5 p-4 text-sm text-rose-200"><XCircle className="mr-2 inline h-4 w-4" />{scan.error_message}</div>}<div className="mt-6 grid gap-4 text-sm text-slate-400 sm:grid-cols-2"><div><span className="text-slate-600">Started</span><p className="mt-1 text-slate-200">{new Date(scan.started_at).toLocaleString()}</p></div><div><span className="text-slate-600">Completed</span><p className="mt-1 text-slate-200">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "In progress"}</p></div></div></div><section className="panel mt-5 overflow-hidden rounded-2xl"><div className="border-b border-slate-800/80 p-5"><div className="eyebrow mb-2">Persisted findings</div><h2 className="text-lg font-semibold text-white">What the scanners found</h2></div><div className="divide-y divide-slate-800/70">{findings.map((finding) => <div key={finding.id} className="flex flex-col gap-2 p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="font-medium text-slate-200">{finding.cve_id || finding.package_name}</div><div className="text-xs text-slate-500">{finding.package_name} {finding.package_version || ""}{finding.fixed_version ? ` → ${finding.fixed_version}` : ""}</div></div><div className="flex items-center gap-3"><span className="rounded-full bg-rose-400/10 px-2.5 py-1 text-xs uppercase text-rose-200">{finding.severity}</span>{finding.fix_available && <span className="text-xs text-emerald-300">fix available</span>}</div></div>)}{!findings.length && <div className="p-6 text-sm text-slate-500">No persisted findings are attached to this scan yet.</div>}</div></section></Layout>;
}
