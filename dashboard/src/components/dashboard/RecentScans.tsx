import Link from "next/link";
import { CheckCircle2, ChevronRight, Clock3, XCircle } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import { cx } from "@/lib/cx";
import type { ScanResult } from "@/types";

function StatusIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 className="h-4 w-4" />;
  if (status === "failed" || status === "partial") return <XCircle className="h-4 w-4" />;
  return <Clock3 className="h-4 w-4" />;
}

function tone(status: string): string {
  if (status === "completed") return "bg-emerald-400/10 text-emerald-300";
  if (status === "failed" || status === "partial") return "bg-rose-400/10 text-rose-300";
  return "bg-amber-400/10 text-amber-300";
}

export default function RecentScans({ scans }: { scans: ScanResult[] }) {
  return (
    <section className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <div className="eyebrow mb-2">Latest activity</div>
          <h3 className="text-lg font-semibold text-white">Recent scans</h3>
        </div>
        <Link href="/scans" className="text-xs font-medium text-cyan-300 hover:text-cyan-200">
          View all <ChevronRight className="inline h-3.5 w-3.5" />
        </Link>
      </div>
      <div className="space-y-2">
        {scans.slice(0, 5).map((scan) => (
          <Link
            href={`/scans/${scan.scan_id}`}
            key={scan.scan_id}
            className={cx(
              "group flex items-center gap-3 rounded-xl border border-transparent p-2 transition",
              "hover:border-slate-700 hover:bg-slate-800/60",
            )}
          >
            <span className={cx("flex h-8 w-8 items-center justify-center rounded-lg", tone(scan.status))}>
              <StatusIcon status={scan.status} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-slate-200">{scan.image_name}</span>
              <span className="text-xs text-slate-600">
                {scan.status} · {new Date(scan.completed_at || scan.started_at).toLocaleString()}
              </span>
            </span>
            <span className="text-right">
              <span className="block text-sm font-semibold text-slate-300">{scan.findings}</span>
              <span className="text-[10px] uppercase tracking-wider text-slate-600">findings</span>
            </span>
          </Link>
        ))}
        {!scans.length && <EmptyState title="No scans yet" description="Run a scan to start building history." />}
      </div>
    </section>
  );
}
