import { cx } from "@/lib/cx";
import type { SystemStatus } from "@/hooks/useSystemStatus";

const TONES = {
  operational: { box: "border-emerald-400/15 bg-emerald-400/[0.05]", text: "text-emerald-300", dot: "bg-emerald-400" },
  degraded: { box: "border-amber-400/20 bg-amber-400/[0.06]", text: "text-amber-300", dot: "bg-amber-400" },
  unavailable: { box: "border-rose-400/20 bg-rose-400/[0.06]", text: "text-rose-300", dot: "bg-rose-400" },
  checking: { box: "border-slate-700/60 bg-slate-800/30", text: "text-slate-400", dot: "bg-slate-500" },
} as const;

const HEADLINES = {
  operational: "All systems operational",
  degraded: "Degraded",
  unavailable: "Unavailable",
  checking: "Checking services…",
} as const;

function relativeTime(value: string | null | undefined): string {
  if (!value) return "";
  const minutes = Math.round((Date.now() - new Date(value).getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : new Date(value).toLocaleDateString();
}

/** "Discovery: 7 running images, 1 local-only skipped, 3 min ago." Errors are listed in `problems`. */
export function discoveryLine(discovery: SystemStatus["discovery"]): string {
  if (!discovery || discovery.status === "disabled" || discovery.status === "error") return "";
  const running = discovery.running_images ?? 0;
  const skipped = (discovery.local_only ?? 0) + (discovery.id_only ?? 0);
  const parts = [`${running} running image${running === 1 ? "" : "s"}`];
  if (skipped) parts.push(`${skipped} not scannable`);
  return ` Discovery: ${parts.join(", ")}, ${relativeTime(discovery.checked_at)}.`;
}

function detail(system: SystemStatus): string {
  if (system.status === "checking") return "Contacting the API.";
  if (system.problems.length) return system.problems.join(" · ") + ".";
  const workers = `${system.workers} scan worker${system.workers === 1 ? "" : "s"} responding`;
  const scan = system.last_scan;
  const discovery = discoveryLine(system.discovery);
  if (!scan) return `${workers}. No scans yet.${discovery}`;
  return `${workers}. Last scan ${scan.status} ${relativeTime(scan.completed_at || scan.started_at)}.${discovery}`;
}

/** Sidebar panel: the API's own report of database, queue, and worker status. */
export function SystemStatusPanel({ system }: { system: SystemStatus }) {
  const tone = TONES[system.status];
  return (
    <div className={cx("mt-auto rounded-2xl border p-4", tone.box)} aria-live="polite">
      <div className={cx("mb-3 flex items-center gap-2 text-sm font-medium", tone.text)}>
        <span className={cx("h-2 w-2 rounded-full", tone.dot)} />
        {HEADLINES[system.status]}
      </div>
      <p className="text-xs leading-5 text-slate-500">{detail(system)}</p>
    </div>
  );
}

/** Compact header indicator with the same source as the sidebar panel. */
export function SystemStatusBadge({ system }: { system: SystemStatus }) {
  const tone = TONES[system.status];
  const label = system.problems[0] || HEADLINES[system.status];
  return (
    <div className={cx("hidden items-center gap-2 text-sm sm:flex", tone.text)} title={detail(system)}>
      <span className={cx("h-2 w-2 rounded-full", tone.dot)} />
      {label}
    </div>
  );
}
