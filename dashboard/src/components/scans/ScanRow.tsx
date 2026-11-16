import Link from "next/link";
import { AlertOctagon, CheckCircle2, Clock3, XCircle } from "lucide-react";
import { cx } from "@/lib/cx";
import { isActiveScan } from "@/lib/status";
import type { ScanResult } from "@/types";

type Props = {
  scan: ScanResult;
  canCancel: boolean;
  selected: boolean;
  onSelect: (checked: boolean) => void;
  onCancel: () => void;
};

function tone(status: string): string {
  if (status === "completed") return "bg-emerald-400/10 text-emerald-300";
  if (status === "failed") return "bg-rose-400/10 text-rose-300";
  if (status === "partial") return "bg-amber-400/10 text-amber-300";
  return "bg-cyan-400/10 text-cyan-300";
}

function runtimeMinutes(scan: ScanResult): number | null {
  if (!scan.completed_at) return null;
  const elapsed = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
  return Math.max(1, Math.round(elapsed / 60000));
}

export default function ScanRow({ scan, canCancel, selected, onSelect, onCancel }: Props) {
  const active = isActiveScan(scan.status);
  const duration = runtimeMinutes(scan);
  const Icon =
    scan.status === "completed" ? CheckCircle2 : scan.status === "failed" ? XCircle : active ? Clock3 : AlertOctagon;
  return (
    <div
      className={cx(
        "group flex flex-col gap-4 p-5 transition hover:bg-slate-800/30",
        "sm:flex-row sm:items-center sm:px-6",
      )}
    >
      <input
        aria-label={`Select ${scan.image_name}`}
        type="checkbox"
        checked={selected}
        onChange={(event) => onSelect(event.target.checked)}
        className="h-4 w-4 accent-cyan-400"
      />
      <Link
        href={`/scans/${scan.scan_id}`}
        className={cx("flex h-10 w-10 shrink-0 items-center justify-center rounded-xl", tone(scan.status))}
      >
        <Icon className="h-5 w-5" />
      </Link>
      <div className="min-w-0 flex-1">
        <Link href={`/scans/${scan.scan_id}`} className="mb-1 flex flex-wrap items-center gap-2">
          <span className="truncate font-mono text-sm text-slate-200">{scan.image_name}</span>
          <span
            className={cx(
              "rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
              tone(scan.status),
            )}
          >
            {scan.status}
          </span>
        </Link>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-600">
          <span className="capitalize text-cyan-300/70">Phase: {(scan.phase || scan.status).replaceAll("_", " ")}</span>
          <span className="hidden text-slate-700 sm:inline">·</span>
          <span>{scan.scan_id}</span>
          <span className="hidden text-slate-700 sm:inline">·</span>
          <span>
            <Clock3 className="mr-1 inline h-3 w-3" />
            {new Date(scan.started_at).toLocaleString()}
          </span>
          {duration && (
            <>
              <span className="hidden text-slate-700 sm:inline">·</span>
              <span>{duration} min runtime</span>
            </>
          )}
        </div>
      </div>
      <div className="flex items-center gap-4 pl-14 sm:pl-0">
        <div className="text-right">
          <div className="text-lg font-semibold text-slate-200">{scan.findings}</div>
          <div className="text-[10px] uppercase tracking-wider text-slate-600">findings</div>
        </div>
        <div className="hidden items-center gap-1.5 text-xs sm:flex">
          <span className="text-rose-300">{scan.critical_count}C</span>
          <span className="text-orange-300">{scan.high_count}H</span>
          <span className="text-yellow-300">{scan.medium_count}M</span>
          <span className="text-blue-300">{scan.low_count}L</span>
        </div>
        {active && canCancel && (
          <button
            onClick={onCancel}
            className={cx(
              "rounded-lg border border-rose-400/20 px-2.5 py-1.5 text-xs text-rose-300",
              "transition hover:bg-rose-400/10",
            )}
          >
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
