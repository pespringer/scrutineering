"use client";

import { useEffect, useState } from "react";
import { ArrowLeft, CheckCircle2, CircleAlert, GitPullRequest, Play, ShieldCheck } from "lucide-react";
import Link from "next/link";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";

type Event = { id: number; event_type: string; sequence: number; detail: Record<string, unknown>; created_at: string };
type LatestEvent = { event_type: string; detail: Record<string, unknown>; created_at: string } | null;
type Publication = {
  id: number;
  provider: string;
  repository: string;
  status: string;
  url: string | null;
  verification_status: string | null;
  scan_status: string | null;
  post_merge_scan_id: string | null;
  verification_detail?: Record<string, unknown>;
  findings_before: number | null;
  findings_after: number | null;
  rollback_command: string[] | null;
};
type Remediation = {
  id: number;
  image_id: number;
  status: string;
  workflow_state?: string;
  workflow_label?: string;
  finding_count: number;
  open_finding_count?: number;
  resolved_finding_count?: number;
  resolution_status?: string;
  actions: Array<{ action_type: string; before_value: string | null; after_value: string | null }>;
  publications: Publication[];
};

const badgeClass = (status: string | null | undefined) =>
  status === "verified" || status === "completed" || status === "ready"
    ? "bg-emerald-400/10 text-emerald-200"
    : status === "rollback_required" || status === "failed" || status === "blocked"
      ? "bg-rose-400/10 text-rose-200"
      : "bg-amber-400/10 text-amber-200";

export default function RemediationDetail({ params }: { params: Promise<{ id: string }> }) {
  const [data, setData] = useState<{ remediation: Remediation; events: Event[]; latest_event?: LatestEvent } | null>(
    null,
  );
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async (id: string) => {
    const [remediation, events] = await Promise.all([
      fetch(`/api/remediations/${id}`, { cache: "no-store" }).then((r) => r.json()),
      fetch(`/api/remediations/${id}/events`, { cache: "no-store" }).then((r) => r.json()),
    ]);
    setData({ remediation, events: events.events || [], latest_event: events.latest_event || null });
  };
  useEffect(() => {
    params.then(({ id }) => load(id)).catch(() => setData(null));
  }, [params]);

  const action = async (path: string, init?: RequestInit) => {
    setBusy(true);
    setNotice("");
    try {
      const response = await fetch(path, init);
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || "Request failed");
      setNotice(body.status ? `Workflow status: ${body.status}` : "Action accepted.");
      if (data) {
        const id = String(data.remediation.id);
        await load(id);
        if (path.endsWith("/execute")) [3000, 8000, 15000].forEach((delay) => window.setTimeout(() => load(id), delay));
      }
      return body;
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Request failed");
      return null;
    } finally {
      setBusy(false);
    }
  };
  const approve = async () => {
    if (!data) return;
    await action(`/api/remediations/${data.remediation.id}/approve`, { method: "POST" });
  };

  if (!data)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  const { remediation, events } = data;
  const latestEvent = data.latest_event;
  const workflowState = remediation.workflow_state || remediation.status;
  const displayStatus = remediation.workflow_label || workflowState.replaceAll("_", " ");
  const executionActive = ["execution_queued", "execution_started", "execution_ready"].includes(workflowState);
  const workflowMessage =
    workflowState === "requires_review"
      ? "Review the proposed changes, then approve the remediation."
      : workflowState === "execution_queued"
        ? "Execution is queued for the remediation worker. This control is locked until the worker reports a result."
        : workflowState === "execution_started"
          ? "The worker is applying and validating the change. This page refreshes automatically as durable events arrive."
          : workflowState === "execution_ready"
            ? "Local execution completed successfully. The validated commit is ready for optional publication or follow-up verification."
            : remediation.status === "failed"
              ? "Execution stopped. Review the failure event below, then restart the workflow if the underlying problem has been corrected."
              : remediation.status === "completed"
                ? "This remediation is complete. Confirm the follow-up scan shows the targeted findings resolved."
                : `Workflow status: ${displayStatus}.`;
  return (
    <Layout>
      <Link href="/remediations" className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300">
        <ArrowLeft className="h-4 w-4" /> Back to remediations
      </Link>
      <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="eyebrow mb-3">Remediation #{remediation.id}</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Governed fix workflow</h1>
          <p className="mt-2 text-sm text-slate-400">
            Image {remediation.image_id} · {remediation.finding_count} finding(s) · {displayStatus}
          </p>
        </div>
        <div
          className={`rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-wider ${badgeClass(displayStatus)}`}
        >
          {displayStatus}
        </div>
      </div>
      {notice && (
        <div className="mb-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-4 text-sm text-cyan-100">
          {notice}
        </div>
      )}
      <section
        className={`mb-6 rounded-2xl border p-5 ${remediation.status === "failed" ? "border-rose-400/20 bg-rose-400/5" : remediation.status === "completed" || workflowState === "execution_ready" ? "border-emerald-400/20 bg-emerald-400/5" : "border-cyan-400/20 bg-cyan-400/5"}`}
      >
        <div className="eyebrow mb-2">What happens next</div>
        <p className="text-sm leading-6 text-slate-200">{workflowMessage}</p>
        {latestEvent && (
          <p className="mt-2 text-xs text-slate-500">
            Latest worker event:{" "}
            <span className="font-medium text-slate-300">{latestEvent.event_type.replaceAll("_", " ")}</span> ·{" "}
            {new Date(latestEvent.created_at).toLocaleString()}
          </p>
        )}
        {latestEvent?.detail?.reason ? (
          <p className="mt-2 rounded-lg bg-rose-950/30 px-3 py-2 text-xs text-rose-200">
            Reason: {String(latestEvent.detail.reason)}
          </p>
        ) : null}
      </section>
      <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
        <section className="space-y-6">
          <div className="panel rounded-2xl p-5 sm:p-6">
            <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
              <ShieldCheck className="h-4 w-4 text-cyan-300" /> Approval and execution
            </div>
            <p className="mb-4 text-sm leading-6 text-slate-400">
              Execution requires approval by a security operator. Once queued, execution is locked until the worker
              reports ready or blocked. A failed run can be deliberately restarted.
            </p>
            <div className="flex flex-wrap gap-3">
              <button
                disabled={busy || remediation.status !== "requires_review"}
                onClick={approve}
                className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Approve remediation
              </button>
              <button
                disabled={busy || remediation.status !== "analyzing" || executionActive}
                onClick={() => action(`/api/remediations/${remediation.id}/execute`, { method: "POST" })}
                className="inline-flex items-center gap-2 rounded-xl border border-violet-400/30 px-4 py-2.5 text-sm text-violet-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Play className="h-4 w-4" />{" "}
                {workflowState === "execution_queued"
                  ? "Execution queued"
                  : workflowState === "execution_started"
                    ? "Execution in progress"
                    : workflowState === "execution_ready"
                      ? "Execution ready"
                      : "Queue execution"}
              </button>
              {remediation.status === "failed" && (
                <button
                  disabled={busy}
                  onClick={() => action(`/api/remediations/${remediation.id}/retry`, { method: "POST" })}
                  className="inline-flex items-center gap-2 rounded-xl border border-rose-400/30 px-4 py-2.5 text-sm text-rose-100 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Restart workflow
                </button>
              )}
            </div>
          </div>
          <div className="panel rounded-2xl p-5 sm:p-6">
            <div className="mb-5 text-sm font-semibold text-slate-200">Proposed changes</div>
            <div className="space-y-3">
              {remediation.actions.map((item, index) => (
                <div key={index} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-sm">
                  <div className="text-slate-300">{item.action_type}</div>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs">
                    <span className="rounded bg-rose-400/10 px-2 py-1 text-rose-200">
                      {item.before_value || "unknown"}
                    </span>
                    <span className="text-slate-600">→</span>
                    <span className="rounded bg-emerald-400/10 px-2 py-1 text-emerald-200">
                      {item.after_value || "unknown"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="panel rounded-2xl p-5 sm:p-6">
            <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
              <CheckCircle2 className="h-4 w-4 text-cyan-300" /> Durable events
            </div>
            <div className="space-y-5">
              {events.map((event) => (
                <div key={event.id} className="flex gap-3">
                  <div className="mt-0.5 text-cyan-300">
                    {event.event_type.includes("rollback") || event.event_type.includes("blocked") ? (
                      <CircleAlert className="h-4 w-4 text-rose-300" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4" />
                    )}
                  </div>
                  <div>
                    <div className="text-sm font-medium text-slate-200">{event.event_type}</div>
                    <div className="text-xs text-slate-500">
                      Step {event.sequence} · {new Date(event.created_at).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
              {!events.length && <p className="text-sm text-slate-500">No lifecycle events yet.</p>}
            </div>
          </div>
        </section>
        <aside className="space-y-6">
          <div className="panel rounded-2xl p-5 sm:p-6">
            <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
              <GitPullRequest className="h-4 w-4 text-violet-300" /> Publications and verification
            </div>
            {remediation.publications.map((publication) => (
              <div key={publication.id} className="border-b border-slate-800 py-4 last:border-0">
                <div className="text-sm text-slate-200">{publication.repository}</div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs uppercase tracking-wider">
                  <span className={`rounded-full px-2 py-1 ${badgeClass(publication.status)}`}>
                    {publication.status}
                  </span>
                  <span className={`rounded-full px-2 py-1 ${badgeClass(publication.verification_status)}`}>
                    {publication.verification_status || "awaiting verification"}
                  </span>
                </div>
                {publication.url && (
                  <a className="mt-2 block truncate text-xs text-cyan-300" href={publication.url} target="_blank">
                    {publication.url}
                  </a>
                )}
                {publication.findings_before !== null && publication.findings_after !== null && (
                  <p className="mt-2 text-xs text-slate-500">
                    Findings {publication.findings_before} → {publication.findings_after}
                    {publication.scan_status ? ` · scan ${publication.scan_status}` : ""}
                  </p>
                )}
              </div>
            ))}
            {!remediation.publications.length && <p className="text-sm text-slate-500">No publication yet.</p>}
          </div>
        </aside>
      </div>
    </Layout>
  );
}
