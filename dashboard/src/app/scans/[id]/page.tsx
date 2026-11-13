"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ScanResult } from "@/types";
import { ArrowLeft, CheckCircle2, Clock3, XCircle } from "lucide-react";
import { useParams } from "next/navigation";

export default function ScanDetailPage() {
  const params = useParams();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetch(`/api/scans/${params.id}`, { cache: "no-store" }).then((response) => response.ok ? response.json() : null).then(setScan).catch(() => setScan(null)).finally(() => setLoading(false)); }, [params.id]);
  if (loading) return <Layout><LoadingSpinner /></Layout>;
  if (!scan) return <Layout><EmptyState title="Scan not found" description="The scan record is unavailable or has been removed." /></Layout>;
  const terminal = ["completed", "failed", "cancelled", "partial"].includes(scan.status);
  return <Layout><Link href="/scans" className="mb-6 inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300"><ArrowLeft className="h-4 w-4" /> Back to scans</Link><div className="panel rounded-2xl p-6"><div className="flex items-start justify-between gap-4"><div><div className="eyebrow mb-2">Scan detail</div><h1 className="break-all font-mono text-2xl font-semibold text-white">{scan.image_name}</h1><p className="mt-2 text-xs text-slate-500">{scan.scan_id}</p></div><span className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-3 py-1.5 text-xs uppercase tracking-wider text-slate-300">{terminal ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <Clock3 className="h-4 w-4 text-cyan-300" />}{scan.status}</span></div><div className="mt-8 grid gap-3 sm:grid-cols-4">{[["Findings", scan.findings], ["Critical", scan.critical_count], ["High", scan.high_count], ["Medium", scan.medium_count]].map(([label, value]) => <div key={label} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4"><div className="eyebrow">{label}</div><div className="mt-2 text-2xl font-semibold text-white">{value}</div></div>)}</div>{scan.error_message && <div className="mt-5 rounded-xl border border-rose-400/20 bg-rose-400/5 p-4 text-sm text-rose-200"><XCircle className="mr-2 inline h-4 w-4" />{scan.error_message}</div>}<div className="mt-6 grid gap-4 text-sm text-slate-400 sm:grid-cols-2"><div><span className="text-slate-600">Started</span><p className="mt-1 text-slate-200">{new Date(scan.started_at).toLocaleString()}</p></div><div><span className="text-slate-600">Completed</span><p className="mt-1 text-slate-200">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "In progress"}</p></div></div></div></Layout>;
}
