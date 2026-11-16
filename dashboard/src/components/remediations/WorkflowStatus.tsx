import { cx } from "@/lib/cx";
import type { RemediationEvent, RemediationRecord } from "@/types";

const MESSAGES: Record<string, string> = {
  requires_review: "Review the proposed changes, then approve the remediation.",
  execution_queued:
    "Execution is queued for the remediation worker. This control is locked until the worker reports a result.",
  execution_started:
    "The worker is applying and validating the change. This page refreshes automatically as events arrive.",
  execution_ready:
    "Execution completed. The validated commit is ready for optional publication or follow-up verification.",
};

function message(remediation: RemediationRecord, workflowState: string, label: string): string {
  if (MESSAGES[workflowState]) return MESSAGES[workflowState];
  if (remediation.status === "failed") {
    return "Execution stopped. Review the failure event below, then restart the workflow once the cause is fixed.";
  }
  if (remediation.status === "completed") {
    return "This remediation is complete. Confirm the follow-up scan shows the targeted findings resolved.";
  }
  return `Workflow status: ${label}.`;
}

type Props = {
  remediation: RemediationRecord;
  workflowState: string;
  label: string;
  latestEvent: Omit<RemediationEvent, "id" | "sequence"> | null;
};

/** "What happens next": the current state in plain words, plus the latest worker event and any blocking reason. */
export default function WorkflowStatus({ remediation, workflowState, label, latestEvent }: Props) {
  const tone =
    remediation.status === "failed"
      ? "border-rose-400/20 bg-rose-400/5"
      : remediation.status === "completed" || workflowState === "execution_ready"
        ? "border-emerald-400/20 bg-emerald-400/5"
        : "border-cyan-400/20 bg-cyan-400/5";
  return (
    <section className={cx("mb-6 rounded-2xl border p-5", tone)}>
      <div className="eyebrow mb-2">What happens next</div>
      <p className="text-sm leading-6 text-slate-200">{message(remediation, workflowState, label)}</p>
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
  );
}
