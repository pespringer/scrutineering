import { Ban, Check, Play, RotateCcw, ShieldCheck } from "lucide-react";
import { cx } from "@/lib/cx";
import type { RemediationRecord, RemediationStatus } from "@/types";

export type RemediationAction = "approve" | "execute" | "accept" | "retry" | "cancel";

const BUTTON =
  "inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm disabled:cursor-not-allowed disabled:opacity-40";
const CANCELLABLE: RemediationStatus[] = [
  "proposed",
  "approved",
  "building",
  "verifying",
  "needs_acceptance",
  "ready",
  "failed",
];

type Props = { remediation: RemediationRecord; busy: boolean; onAction: (action: RemediationAction) => void };

/** Only the actions the current status allows are shown. */
export default function ExecutionControls({ remediation, busy, onAction }: Props) {
  const status = remediation.status;
  if (status === "completed" || status === "cancelled") return null;
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <ShieldCheck className="h-4 w-4 text-cyan-300" /> Approval and execution
      </div>
      <div className="flex flex-wrap gap-3">
        {status === "proposed" && (
          <button
            disabled={busy}
            onClick={() => onAction("approve")}
            className={cx(BUTTON, "bg-cyan-400 font-semibold text-slate-950")}
          >
            <Check className="h-4 w-4" /> Approve
          </button>
        )}
        {status === "approved" && (
          <button
            disabled={busy}
            onClick={() => onAction("execute")}
            className={cx(BUTTON, "bg-violet-400 font-semibold text-slate-950")}
          >
            <Play className="h-4 w-4" /> Build and verify
          </button>
        )}
        {status === "needs_acceptance" && (
          <button
            disabled={busy}
            onClick={() => onAction("accept")}
            className={cx(BUTTON, "bg-amber-400 font-semibold text-slate-950")}
          >
            <Check className="h-4 w-4" /> Accept new findings
          </button>
        )}
        {status === "failed" && (
          <button
            disabled={busy}
            onClick={() => onAction("retry")}
            className={cx(BUTTON, "border border-rose-400/30 text-rose-100")}
          >
            <RotateCcw className="h-4 w-4" /> Restart workflow
          </button>
        )}
        {CANCELLABLE.includes(status) && (
          <button
            disabled={busy}
            onClick={() => onAction("cancel")}
            className={cx(BUTTON, "border border-slate-700 text-slate-300")}
          >
            <Ban className="h-4 w-4" /> Cancel
          </button>
        )}
        {(status === "building" || status === "verifying") && (
          <span className="self-center text-sm text-slate-400">Working… this page refreshes itself.</span>
        )}
      </div>
    </div>
  );
}
