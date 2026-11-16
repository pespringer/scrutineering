import type { RemediationAction } from "@/types";

export default function ProposedChanges({ actions }: { actions: RemediationAction[] }) {
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-5 text-sm font-semibold text-slate-200">Proposed changes</div>
      <div className="space-y-3">
        {actions.map((action, index) => (
          <div key={index} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-sm">
            <div className="text-slate-300">
              {action.detail?.description || action.action_type.replaceAll("_", " ")}
              {action.file_path && <span className="ml-2 font-mono text-xs text-slate-500">{action.file_path}</span>}
            </div>
            <div className="mt-2 flex flex-wrap gap-2 text-xs">
              <span className="rounded bg-rose-400/10 px-2 py-1 text-rose-200">{action.before_value || "unknown"}</span>
              <span className="text-slate-600">→</span>
              <span className="rounded bg-emerald-400/10 px-2 py-1 text-emerald-200">
                {action.after_value || "unknown"}
              </span>
            </div>
          </div>
        ))}
        {!actions.length && <p className="text-sm text-slate-500">No proposed changes.</p>}
      </div>
    </div>
  );
}
