import { GitPullRequest } from "lucide-react";
import { cx } from "@/lib/cx";
import { statusTone } from "@/lib/status";
import type { RemediationPublication } from "@/types";

const STATUS_LABEL: Record<RemediationPublication["status"], string> = {
  open: "open",
  merged: "merged",
  closed: "closed unmerged",
  failed: "could not open",
};

/** The GitHub pull request this remediation was published as, or why it could not be opened. */
export default function Publications({ publications }: { publications: RemediationPublication[] }) {
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <GitPullRequest className="h-4 w-4 text-violet-300" /> Pull request
      </div>
      {publications.map((publication) => (
        <div key={publication.id} className="border-b border-slate-800 py-4 last:border-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-slate-200">
              {publication.repository}
              {publication.number ? ` #${publication.number}` : ""}
            </span>
            <span
              className={cx("rounded-full px-2 py-1 text-xs uppercase tracking-wider", statusTone(publication.status))}
            >
              {STATUS_LABEL[publication.status] || publication.status}
            </span>
          </div>
          {publication.branch && (
            <p className="mt-2 break-all font-mono text-xs text-slate-400">
              {publication.branch}
              {publication.base_branch ? ` → ${publication.base_branch}` : ""}
            </p>
          )}
          {publication.url && (
            <a
              className="mt-2 block truncate text-xs text-cyan-300"
              href={publication.url}
              target="_blank"
              rel="noreferrer"
            >
              {publication.url}
            </a>
          )}
          {publication.error_message && (
            <p className="mt-2 rounded-lg bg-rose-950/30 px-3 py-2 text-xs text-rose-200">
              {publication.error_message}
            </p>
          )}
        </div>
      ))}
      {!publications.length && <p className="text-sm text-slate-500">Not published.</p>}
    </div>
  );
}
