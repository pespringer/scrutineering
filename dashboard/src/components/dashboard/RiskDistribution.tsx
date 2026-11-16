import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { cx } from "@/lib/cx";
import type { PostureSummary } from "@/types";

export default function RiskDistribution({ posture }: { posture: PostureSummary }) {
  const levels = [
    { label: "Critical", count: posture.critical_count, color: "#ff647c" },
    { label: "High", count: posture.high_count, color: "#ff9f5b" },
    { label: "Medium", count: posture.medium_count, color: "#f5cf6b" },
    { label: "Low", count: posture.low_count, color: "#55a6ff" },
  ];
  const total = Math.max(
    levels.reduce((sum, level) => sum + level.count, 0),
    1,
  );
  return (
    <section className="panel rounded-2xl p-5 sm:p-6">
      <div className="eyebrow mb-2">Triage queue</div>
      <h3 className="text-lg font-semibold text-white">Risk distribution</h3>
      <p className="mt-1 text-sm text-slate-500">Where to focus your next remediation cycle.</p>
      <div className="my-8 flex h-3 overflow-hidden rounded-full bg-slate-800">
        {levels.map((level) => (
          <div key={level.label} style={{ width: `${(level.count / total) * 100}%`, backgroundColor: level.color }} />
        ))}
      </div>
      <div className="space-y-4">
        {levels.map((level) => (
          <div key={level.label} className="flex items-center gap-3">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: level.color }} />
            <span className="flex-1 text-sm text-slate-300">{level.label}</span>
            <span className="font-mono text-sm text-white">{level.count}</span>
            <span className="w-10 text-right text-xs text-slate-600">{Math.round((level.count / total) * 100)}%</span>
          </div>
        ))}
      </div>
      <Link
        href="/images"
        className={cx(
          "mt-8 flex items-center justify-between rounded-xl border border-slate-700/80 bg-slate-800/40 px-4 py-3",
          "text-sm font-medium text-slate-300 transition hover:border-cyan-400/30 hover:text-cyan-200",
        )}
      >
        Triage by image <ArrowRight className="h-4 w-4" />
      </Link>
    </section>
  );
}
