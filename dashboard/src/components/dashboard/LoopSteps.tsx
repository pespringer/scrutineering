import { cx } from "@/lib/cx";

const STEPS = [
  ["1", "Discover", "Inventory or targeted image"],
  ["2", "Scan", "Trivy + Grype workers"],
  ["3", "Decide", "Normalize and prioritize"],
  ["4", "Remediate", "Review and execute a fix"],
  ["5", "Verify", "Rescan and close the loop"],
] as const;

/** The core loop every finding follows, shown on the overview page. */
export default function LoopSteps() {
  return (
    <section className="panel mb-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-4">
        <div className="eyebrow mb-2">How the control plane works</div>
        <h2 className="text-lg font-semibold text-white">From image to resolved risk</h2>
        <p className="mt-1 text-sm text-slate-500">
          Every finding follows this path. The dashboard links each step to its durable record.
        </p>
      </div>
      <div className="grid gap-3 md:grid-cols-5">
        {STEPS.map(([number, title, detail]) => (
          <div key={number} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
            <div
              className={cx(
                "mb-3 flex h-7 w-7 items-center justify-center rounded-full bg-cyan-400/10",
                "text-xs font-bold text-cyan-200",
              )}
            >
              {number}
            </div>
            <div className="text-sm font-medium text-slate-200">{title}</div>
            <div className="mt-1 text-xs leading-5 text-slate-500">{detail}</div>
          </div>
        ))}
      </div>
      <div
        className={cx(
          "mt-4 rounded-xl border border-amber-400/15 bg-amber-400/[0.04] px-4 py-3",
          "text-xs leading-5 text-amber-200/80",
        )}
      >
        Publishing fixes as pull requests is optional and stays off until a provider is configured. Scanning, findings,
        remediation, and verification work without it.
      </div>
    </section>
  );
}
