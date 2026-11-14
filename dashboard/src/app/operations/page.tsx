"use client";

import { useEffect, useState } from "react";
import { Activity, CheckCircle2, CircleAlert, Gauge, RefreshCw } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import ControlPlaneHealth from "@/components/ControlPlaneHealth";

type OperationalCheck = { status: string; message: string; depths?: Record<string, number>; workers?: string[]; worker_details?: { name: string; active: number; reserved: number; scheduled: number }[]; latest_artifact?: string | null; latest_size_bytes?: number | null; latest_verified?: boolean; latest_backup_id?: number | null; latest_restore?: { status: string; cleanup_verified: boolean } | null };
type Retention = { cutoff: string; retention_days: number; eligible_scans: number; eligible_findings: number; purge_enabled: boolean; dry_run: boolean };
type FailedScan = { scan_id: string; image_name: string; started_at: string; error_message?: string | null };
type RuntimeEvents = { status: string; message?: string; checkpoint_offset?: number | null; pending_count?: number; events: { timestamp?: number; event_type?: string; container_id?: string; image_name?: string | null; severity?: string; source?: string }[] };
type Operations = { panels: { key: string; title: string; metric: string; unit: string; threshold?: number }[]; telemetry?: { http_requests: number; http_5xx: number; http_error_rate: number; http_latency_p95_seconds: number | null; scan_failures: number; runtime_dead_letters: number }; scorecard: { status: string; checks: Record<string, boolean>; passed: number; total: number }; checks?: Record<string, OperationalCheck>; deferred_checks?: Record<string, { status: string; message: string } | Record<string, unknown>>; receiver_delivery: { enabled: boolean; deferred: boolean } };

function formatBytes(value: number | null | undefined) {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export default function OperationsPage() {
  const [data, setData] = useState<Operations | null>(null);
  const [error, setError] = useState(false);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupNotice, setBackupNotice] = useState<string | null>(null);
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [retention, setRetention] = useState<Retention | null>(null);
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [failedScans, setFailedScans] = useState<FailedScan[]>([]);
  const [retryBusy, setRetryBusy] = useState(false);
  const [runtimeEvents, setRuntimeEvents] = useState<RuntimeEvents | null>(null);
  const load = () => Promise.all([fetch("/api/production-operations", { cache: "no-store" }), fetch("/api/retention/scans", { cache: "no-store" }), fetch("/api/scans?status=failed&limit=100", { cache: "no-store" }), fetch("/api/runtime/events?limit=25", { cache: "no-store" })]).then(async ([operationsResponse, retentionResponse, failedResponse, runtimeResponse]) => { if (!operationsResponse.ok) throw new Error(); setData(await operationsResponse.json()); if (retentionResponse.ok) setRetention(await retentionResponse.json()); if (failedResponse.ok) { const payload = await failedResponse.json(); setFailedScans(payload.items || []); } if (runtimeResponse.ok) setRuntimeEvents(await runtimeResponse.json()); }).catch(() => setError(true));
  useEffect(() => { load(); }, []);
  const runBackup = async () => {
    setBackupBusy(true);
    setBackupNotice(null);
    try {
      const response = await fetch("/api/backup-evidence", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true }) });
      if (!response.ok) throw new Error(response.status === 409 ? "Backup execution is disabled in configuration." : "Backup request was rejected.");
      setBackupNotice("Backup queued. Refresh shortly for artifact evidence.");
      await load();
    } catch (value) {
      setBackupNotice(value instanceof Error ? value.message : "Backup request failed.");
    } finally { setBackupBusy(false); }
  };
  const verifyRestore = async (backupId: number) => {
    setRestoreBusy(true);
    setBackupNotice(null);
    try {
      const response = await fetch(`/api/backup-evidence?backup_id=${encodeURIComponent(backupId)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true }) });
      if (!response.ok) throw new Error(response.status === 409 ? "Restore verification is disabled or not configured." : "Restore verification was rejected.");
      setBackupNotice("Restore verification queued. Refresh shortly for recovery evidence.");
      await load();
    } catch (value) {
      setBackupNotice(value instanceof Error ? value.message : "Restore verification failed.");
    } finally { setRestoreBusy(false); }
  };
  const queueRetention = async (dryRun: boolean) => {
    if (!dryRun && !window.confirm("Queue deletion of scans older than the configured retention period?")) return;
    setRetentionBusy(true); setBackupNotice(null);
    try {
      const response = await fetch("/api/retention/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true, dry_run: dryRun, limit: 500 }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || "Retention request was rejected.");
      setBackupNotice(dryRun ? "Retention preview queued." : "Retention purge queued. The audit trail records this request.");
      await load();
    } catch (value) { setBackupNotice(value instanceof Error ? value.message : "Retention request failed."); }
    finally { setRetentionBusy(false); }
  };
  const retryFailedScans = async () => {
    if (!failedScans.length || !window.confirm(`Retry ${failedScans.length} failed scan(s)?`)) return;
    setRetryBusy(true); setBackupNotice(null);
    try {
      const response = await fetch("/api/scans/bulk-retry", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ids: failedScans.map((scan) => scan.scan_id) }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || "Retry request was rejected.");
      setBackupNotice(`${body.count || 0} failed scan(s) queued for retry.`);
      await load();
    } catch (value) { setBackupNotice(value instanceof Error ? value.message : "Retry request failed."); }
    finally { setRetryBusy(false); }
  };
  if (!data && !error) return <Layout><LoadingSpinner /></Layout>;
  const scorecard = data?.scorecard;
  return <Layout>
    <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end"><div><div className="eyebrow mb-3">Operations / Production maturity</div><h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Operational readiness</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Receiver-independent health for scans, recovery, providers, backups, and release promotion.</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm text-slate-300 hover:text-white"><RefreshCw className="h-4 w-4" />Refresh</button></div>
    {error ? <div className="panel rounded-2xl p-6 text-sm text-rose-300">Operational telemetry is unavailable. Check the dashboard API connection.</div> : <><ControlPlaneHealth />
      <section className={`mb-6 rounded-2xl border p-6 ${scorecard?.status === "ready" ? "border-emerald-400/20 bg-emerald-400/[.05]" : "border-amber-400/20 bg-amber-400/[.05]"}`}><div className="flex items-start justify-between gap-4"><div><div className="eyebrow mb-2">Promotion scorecard</div><h2 className="text-2xl font-semibold text-white">{scorecard?.status === "ready" ? "Ready for review" : "Attention required"}</h2><p className="mt-2 text-sm text-slate-400">{scorecard?.passed}/{scorecard?.total} receiver-independent checks passing.</p></div><Gauge className="h-8 w-8 text-cyan-300" /></div><div className="mt-5 grid gap-2 sm:grid-cols-5">{Object.entries(scorecard?.checks || {}).map(([key, passed]) => <div key={key} className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-950/30 px-3 py-2 text-xs text-slate-300">{passed ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-300" />}{key}</div>)}</div></section>
      <section className="mb-6 grid gap-4 sm:grid-cols-3">{Object.entries(data?.checks || {}).map(([key, check]) => <div key={key} className="panel rounded-2xl p-5"><div className="mb-3 flex items-center gap-2"><div className="eyebrow">{key}</div>{check.status === "ready" ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-300" />}</div><p className="text-sm text-slate-300">{check.message}</p>{check.depths && <p className="mt-3 font-mono text-xs text-slate-500">{Object.entries(check.depths).map(([queue, depth]) => `${queue}: ${depth}`).join(" · ")}</p>}{check.worker_details && <div className="mt-3 space-y-1 border-t border-slate-800 pt-3 text-xs text-slate-500">{check.worker_details.map((worker) => <div key={worker.name} className="flex items-center justify-between gap-3"><span className="truncate font-mono text-slate-400">{worker.name}</span><span>{worker.active} active · {worker.reserved} reserved · {worker.scheduled} scheduled</span></div>)}</div>}{key === "backup" && <div className="mt-4 border-t border-slate-800 pt-3 text-xs text-slate-500"><div className="truncate text-slate-300">{check.latest_artifact || "No artifact observed"}</div><div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1"><span>{formatBytes(check.latest_size_bytes)}</span><span>{check.latest_verified ? "verified" : "unverified"}</span><button onClick={runBackup} disabled={backupBusy} className="ml-auto rounded-lg border border-cyan-400/20 px-2 py-1 text-cyan-200 disabled:opacity-50">{backupBusy ? "Queuing…" : "Run backup"}</button>{check.latest_backup_id && check.latest_verified && <button onClick={() => verifyRestore(check.latest_backup_id!)} disabled={restoreBusy} className="rounded-lg border border-emerald-400/20 px-2 py-1 text-emerald-200 disabled:opacity-50">{restoreBusy ? "Queuing…" : "Verify restore"}</button>}</div>{check.latest_restore && <p className="mt-2 text-slate-400">Restore: {check.latest_restore.status}{check.latest_restore.cleanup_verified ? " · target cleaned" : ""}</p>}{backupNotice && <p className="mt-2 text-amber-200">{backupNotice}</p>}</div>}</div>)}</section>
      <section className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start"><div><div className="eyebrow mb-2">Data lifecycle</div><h2 className="text-lg font-semibold text-white">Scan retention</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Preview records older than the configured retention window before requesting a cleanup task. Purge stays disabled unless explicitly enabled in service configuration.</p></div><div className="flex flex-wrap gap-2"><button onClick={() => queueRetention(true)} disabled={retentionBusy} className="rounded-lg border border-cyan-400/20 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50">{retentionBusy ? "Queuing…" : "Queue preview"}</button><button onClick={() => queueRetention(false)} disabled={retentionBusy || !retention?.purge_enabled || !retention?.eligible_scans} className="rounded-lg border border-rose-400/20 px-3 py-2 text-xs text-rose-200 disabled:opacity-40">Queue purge</button></div></div>{retention && <div className="mt-5 grid gap-3 sm:grid-cols-4"><div><div className="eyebrow">Window</div><div className="mt-1 text-lg font-semibold text-white">{retention.retention_days} days</div></div><div><div className="eyebrow">Eligible scans</div><div className="mt-1 text-lg font-semibold text-amber-200">{retention.eligible_scans}</div></div><div><div className="eyebrow">Attached findings</div><div className="mt-1 text-lg font-semibold text-amber-200">{retention.eligible_findings}</div></div><div><div className="eyebrow">Purge mode</div><div className="mt-1 text-sm text-slate-300">{retention.purge_enabled ? "enabled by configuration" : "dry-run only"}</div></div></div>}{retention && <p className="mt-4 text-xs text-slate-600">Cutoff: {new Date(retention.cutoff).toLocaleString()}</p>}</section>
      <section className="mb-6 grid gap-4 sm:grid-cols-3 lg:grid-cols-6">{[["API requests", data?.telemetry?.http_requests ?? 0], ["API 5xx", data?.telemetry?.http_5xx ?? 0], ["Error rate", `${((data?.telemetry?.http_error_rate ?? 0) * 100).toFixed(1)}%`], ["API P95", data?.telemetry?.http_latency_p95_seconds === null || data?.telemetry?.http_latency_p95_seconds === undefined ? "—" : `${data.telemetry.http_latency_p95_seconds.toFixed(2)}s`], ["Scan failures", data?.telemetry?.scan_failures ?? 0], ["Dead letters", data?.telemetry?.runtime_dead_letters ?? 0]].map(([label, value]) => <div key={String(label)} className="panel rounded-2xl p-4"><div className="eyebrow">{label}</div><div className="mt-2 text-xl font-semibold text-white">{value}</div><div className="mt-1 text-xs text-slate-500">live registry</div></div>)}</section>
      <section className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start"><div><div className="eyebrow mb-2">Recovery queue</div><h2 className="text-lg font-semibold text-white">Failed scans</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Retry failed scans without hunting through scan history. Each retry creates a new scan record and an audit event; the failed record remains available for diagnosis.</p></div><button onClick={retryFailedScans} disabled={retryBusy || !failedScans.length} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-cyan-400/20 px-4 py-2.5 text-sm text-cyan-200 disabled:opacity-40"><RefreshCw className={`h-4 w-4 ${retryBusy ? "animate-spin" : ""}`} />{retryBusy ? "Retrying…" : `Retry ${failedScans.length || "failed"}`}</button></div>{failedScans.length ? <div className="mt-5 grid gap-2 sm:grid-cols-2">{failedScans.slice(0, 10).map((scan) => <div key={scan.scan_id} className="rounded-xl border border-slate-800 bg-slate-950/30 p-3"><div className="truncate font-mono text-sm text-slate-200">{scan.image_name}</div><div className="mt-1 truncate text-xs text-slate-500">{scan.error_message || "No error detail recorded"}</div><div className="mt-1 font-mono text-[10px] text-slate-700">{scan.scan_id}</div></div>)}{failedScans.length > 10 && <p className="text-xs text-slate-500">Showing 10 of {failedScans.length} failed scans.</p>}</div> : <p className="mt-5 rounded-xl border border-emerald-400/15 bg-emerald-400/[.04] p-4 text-sm text-emerald-200">No failed scans require recovery.</p>}{backupNotice && <p className="mt-3 text-sm text-cyan-200">{backupNotice}</p>}</section>
      <section className="panel mb-6 rounded-2xl p-5 sm:p-6"><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start"><div><div className="eyebrow mb-2">Runtime delivery</div><h2 className="text-lg font-semibold text-white">Replayable event backlog</h2><p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Shows bounded events waiting after the durable replay checkpoint. Payload details are intentionally redacted; use the audit trail for operator actions.</p></div><span className={`rounded-full border px-3 py-1 text-xs ${runtimeEvents?.status === "ready" ? "border-cyan-400/20 text-cyan-200" : "border-slate-700 text-slate-500"}`}>{runtimeEvents?.status === "ready" ? `${runtimeEvents.pending_count || 0} pending` : "Not mounted"}</span></div>{runtimeEvents?.status === "ready" && runtimeEvents.events.length ? <div className="mt-5 space-y-2">{runtimeEvents.events.map((event, index) => <div key={`${event.timestamp}-${index}`} className="flex flex-col gap-1 rounded-xl border border-slate-800 bg-slate-950/30 p-3 text-xs sm:flex-row sm:items-center sm:justify-between"><div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1"><span className="font-mono text-slate-500">{event.event_type || "event"}</span><span className="truncate text-slate-300">{event.image_name || event.container_id || "unknown runtime"}</span></div><span className="text-slate-600">{event.severity || "normal"} · {event.source || "runtime"}</span></div>)}</div> : <p className="mt-5 rounded-xl border border-slate-800 bg-slate-950/30 p-4 text-sm text-slate-500">{runtimeEvents?.message || "No pending runtime events."}</p>}</section>
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{(data?.panels || []).map((panel) => <div key={panel.key} className="panel rounded-2xl p-5"><div className="mb-4 flex items-center justify-between"><div className="eyebrow">{panel.title}</div><Activity className="h-4 w-4 text-cyan-300" /></div><div className="font-mono text-xs text-slate-500">{panel.metric}</div><div className="mt-2 text-sm text-slate-300">Live {panel.unit} telemetry</div>{panel.threshold !== undefined && <div className="mt-3 text-xs text-slate-600">Target threshold: {panel.threshold} {panel.unit}</div>}</div>)}</section>
      <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/30 p-4 text-xs text-slate-500">External alert receiver delivery is disabled and remains a separate operator-gated validation track.</div>
    </>}
  </Layout>;
}
