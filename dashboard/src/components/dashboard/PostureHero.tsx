import Link from "next/link";
import { CheckCircle2, Clock3, XCircle } from "lucide-react";
import { cx } from "@/lib/cx";
import type { PostureSummary } from "@/types";

/** Headline posture: what is tracked, what is open, and when the last scan ran. Reflects real data only. */
export default function PostureHero({ posture }: { posture: PostureSummary }) {
  const empty = posture.total_scanned_images === 0;
  const lastScanFailed = posture.last_scan_status === "failed" || posture.last_scan_status === "partial";
  const healthyShare = Math.max(12, 100 - Math.min(88, posture.total_findings * 2));
  return (
    <section className="panel relative mb-6 overflow-hidden rounded-3xl p-6 sm:p-8">
      <div className="absolute -right-24 -top-32 h-80 w-80 rounded-full bg-cyan-400/10 blur-3xl" />
      <div className="relative flex flex-col justify-between gap-8 lg:flex-row lg:items-center">
        <div className="max-w-xl">
          <h2 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            {empty ? "No images scanned yet." : `${posture.total_findings} open findings across your images.`}
          </h2>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            {empty ? (
              <>
                Push an image to the local registry or{" "}
                <Link href="/scans" className="text-cyan-300 underline underline-offset-4">
                  start a scan
                </Link>{" "}
                to begin tracking findings.
              </>
            ) : (
              <>
                {posture.total_scanned_images} images are tracked. {posture.fixable_count} findings have a known fixed
                version.
              </>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-6">
          <div
            className="relative flex h-32 w-32 items-center justify-center rounded-full"
            style={{ background: `conic-gradient(#38d39f ${healthyShare}%, #1b2a3b 0)` }}
          >
            <div className="flex h-24 w-24 flex-col items-center justify-center rounded-full bg-[#101925]">
              <span className="text-2xl font-bold text-white">{posture.total_findings}</span>
              <span className="text-[10px] uppercase tracking-wider text-slate-500">open issues</span>
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-slate-200">Last scan</div>
            <div
              className={cx(
                "mt-2 flex items-center gap-2 text-xs",
                posture.last_scan_status === "completed" && "text-emerald-300",
                lastScanFailed && "text-rose-300",
                !posture.last_scan_status && "text-slate-500",
              )}
            >
              {posture.last_scan_status === "completed" ? (
                <CheckCircle2 className="h-3.5 w-3.5" />
              ) : lastScanFailed ? (
                <XCircle className="h-3.5 w-3.5" />
              ) : (
                <Clock3 className="h-3.5 w-3.5" />
              )}
              {posture.last_scan_status || "none yet"}
            </div>
            <div className="mt-1 text-xs text-slate-500">
              {posture.last_scan_at ? new Date(posture.last_scan_at).toLocaleString() : "never"}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
