"use client";

import { useEffect, useState } from "react";
import { FileCheck2, RefreshCw } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Report = { id: number; title: string; report_format: string; generated_at: string | null; summary: { report?: { overall_status: string; compliance_percent: number; controls_compliant: number; controls_total: number }; content?: string | null } };

export default function CompliancePage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [framework, setFramework] = useState("nist");
  const [format, setFormat] = useState("json");
  const [canManage, setCanManage] = useState(false);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try { const response = await fetch("/api/compliance/reports", { cache: "no-store" }); if (!response.ok) throw new Error(); setReports((await response.json()).items || []); }
    catch { setNotice("Compliance reports are unavailable."); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); fetch("/api/permissions", { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then((value) => setCanManage(Boolean(value?.can_manage_policies))).catch(() => undefined); }, []);

  async function generate() {
    const response = await fetch("/api/compliance/reports", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ framework, output_format: format }) });
    if (!response.ok) { setNotice("Unable to generate the report."); return; }
    setNotice("Compliance report generated from live posture and audit data."); await load();
  }

  if (loading && !reports.length) return <Layout><LoadingSpinner /></Layout>;
  return <Layout>
    <div className="mb-8 flex items-end justify-between gap-4"><div><div className="eyebrow mb-3">Governance / Evidence</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Compliance reports</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Generate durable, auditable framework reports from the current image posture and audit trail.</p></div><button onClick={load} aria-label="Refresh compliance reports" className="rounded-xl border border-slate-700 bg-slate-900/80 p-3 text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" /></button></div>
    {canManage ? <section className="panel mb-6 flex flex-col gap-4 rounded-2xl p-5 sm:flex-row sm:items-end sm:justify-between"><div><div className="eyebrow mb-2">Generate report</div><div className="flex flex-wrap gap-3"><select value={framework} onChange={(event) => setFramework(event.target.value)} className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200"><option value="nist">NIST SP 800-190</option><option value="pci_dss">PCI DSS 4.0</option><option value="soc2">SOC 2 Type II</option><option value="hipaa">HIPAA Security Rule</option><option value="gdpr">GDPR Article 32</option></select><select value={format} onChange={(event) => setFormat(event.target.value)} className="rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-200"><option value="json">JSON</option><option value="markdown">Markdown</option></select></div></div><button onClick={generate} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300"><FileCheck2 className="h-4 w-4" />Generate report</button></section> : <div className="panel mb-6 rounded-2xl p-5 text-sm text-slate-400">Your role can review reports but cannot generate new compliance evidence.</div>}
    {notice && <p className="mb-4 text-sm text-cyan-200">{notice}</p>}
    <section className="space-y-3">{reports.map((report) => { const summary = report.summary?.report; return <article key={report.id} className="panel rounded-2xl p-5"><div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="font-semibold text-white">{report.title}</h2><p className="mt-1 text-xs text-slate-500">{report.report_format} · {report.generated_at ? new Date(report.generated_at).toLocaleString() : "unknown time"}</p></div>{summary && <div className="text-right"><div className={`text-xl font-semibold ${summary.overall_status === "compliant" ? "text-emerald-300" : "text-amber-200"}`}>{summary.compliance_percent}%</div><div className="text-xs text-slate-500">{summary.controls_compliant}/{summary.controls_total} controls</div></div>}</div>{report.summary?.content && <details className="mt-4"><summary className="cursor-pointer text-xs text-cyan-300">Show Markdown evidence</summary><pre className="mt-3 max-h-80 overflow-auto rounded-xl bg-slate-950/60 p-4 text-xs leading-5 text-slate-300">{report.summary.content}</pre></details>}</article>; })}{!reports.length && <div className="panel rounded-2xl p-8 text-center text-sm text-slate-500">No compliance reports have been generated.</div>}</section>
  </Layout>;
}
