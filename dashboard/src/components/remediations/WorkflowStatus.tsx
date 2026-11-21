import { cx } from "@/lib/cx";
import type { RemediationRecord, RemediationStatus } from "@/types";

const NEXT_STEP: Record<RemediationStatus, string> = {
  proposed: "Review the proposed changes. A security operator approves before anything is built.",
  approved: "Approved. Start execution to apply the changes and build a patched image.",
  building: "Applying the changes to a fresh checkout and building the patched image. This page refreshes itself.",
  verifying: "Scanning the patched image with the same scanners. This page refreshes itself.",
  needs_acceptance:
    "The patched image fixes the targeted findings but adds new critical or high findings. " +
    "A security operator must accept it, or cancel the remediation.",
  ready:
    "The patched image is verified. Open a pull request with the patch, or apply it yourself. The remediation " +
    "completes when a full rescan of this image no longer shows the targeted findings.",
  published:
    "The pull request is open. Once it is merged and the image is rebuilt, the next full scan of the image " +
    "completes the remediation, or fails it if the targeted findings are still there.",
  completed: "Completed: a full rescan of the image no longer shows the targeted findings.",
  failed: "Stopped. Read the reason below, fix the cause, then restart the workflow.",
  cancelled: "Cancelled. Its findings are free to be proposed again.",
};

const TONE: Partial<Record<RemediationStatus, string>> = {
  failed: "border-rose-400/20 bg-rose-400/5",
  needs_acceptance: "border-amber-400/20 bg-amber-400/5",
  ready: "border-emerald-400/20 bg-emerald-400/5",
  published: "border-cyan-400/20 bg-cyan-400/5",
  completed: "border-emerald-400/20 bg-emerald-400/5",
  cancelled: "border-slate-700 bg-slate-900/40",
};

const STEPS: [keyof RemediationRecord, string][] = [
  ["proposed_by", "Proposed by"],
  ["approved_by", "approved by"],
  ["executed_by", "built by"],
  ["accepted_by", "new findings accepted by"],
  ["published_by", "published by"],
];

/** "What happens next": the current status in plain words, plus the failure reason when there is one. */
export default function WorkflowStatus({ remediation }: { remediation: RemediationRecord }) {
  return (
    <section
      className={cx("mb-6 rounded-2xl border p-5", TONE[remediation.status] || "border-cyan-400/20 bg-cyan-400/5")}
    >
      <div className="eyebrow mb-2">What happens next</div>
      <p className="text-sm leading-6 text-slate-200">{NEXT_STEP[remediation.status] || remediation.status_label}</p>
      {remediation.error_message && (
        <p className="mt-2 rounded-lg bg-rose-950/30 px-3 py-2 text-xs text-rose-200">
          Reason: {remediation.error_message}
        </p>
      )}
      <WhoDidWhat remediation={remediation} />
    </section>
  );
}

function WhoDidWhat({ remediation }: { remediation: RemediationRecord }) {
  const steps = STEPS.filter(([key]) => remediation[key]).map(([key, label]) => `${label} ${remediation[key]}`);
  if (steps.length === 0) return null;
  const text = steps.join(" · ");
  return <p className="mt-3 text-xs text-slate-400">{text.charAt(0).toUpperCase() + text.slice(1)}</p>;
}
