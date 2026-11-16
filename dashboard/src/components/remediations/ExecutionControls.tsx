import { Play, ShieldCheck } from "lucide-react";
import { cx } from "@/lib/cx";
import type { RemediationRecord } from "@/types";

const EXECUTE_LABELS: Record<string, string> = {
  execution_queued: "Execution queued",
  execution_started: "Execution in progress",
  execution_ready: "Execution ready",
};

const BUTTON =
  "inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm disabled:cursor-not-allowed disabled:opacity-40";

type Props = {
  remediation: RemediationRecord;
  workflowState: string;
  busy: boolean;
  onAction: (action: "approve" | "execute" | "retry") => void;
};

export default function ExecutionControls({ remediation, workflowState, busy, onAction }: Props) {
  const executionLocked = Boolean(EXECUTE_LABELS[workflowState]);
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <ShieldCheck className="h-4 w-4 text-cyan-300" /> Approval and execution
      </div>
      <p className="mb-4 text-sm leading-6 text-slate-400">
        Execution requires approval by a security operator. Once queued, execution is locked until the worker reports
        ready or blocked. A failed run can be deliberately restarted.
      </p>
      <div className="flex flex-wrap gap-3">
        <button
          disabled={busy || remediation.status !== "requires_review"}
          onClick={() => onAction("approve")}
          className={cx(BUTTON, "bg-cyan-400 font-semibold text-slate-950")}
        >
          Approve remediation
        </button>
        <button
          disabled={busy || remediation.status !== "analyzing" || executionLocked}
          onClick={() => onAction("execute")}
          className={cx(BUTTON, "border border-violet-400/30 text-violet-100")}
        >
          <Play className="h-4 w-4" /> {EXECUTE_LABELS[workflowState] || "Queue execution"}
        </button>
        {remediation.status === "failed" && (
          <button
            disabled={busy}
            onClick={() => onAction("retry")}
            className={cx(BUTTON, "border border-rose-400/30 text-rose-100")}
          >
            Restart workflow
          </button>
        )}
      </div>
    </div>
  );
}
