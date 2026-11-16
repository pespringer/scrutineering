import { GitPullRequest } from "lucide-react";
import { cx } from "@/lib/cx";
import { statusTone } from "@/lib/status";
import type { RemediationPublication } from "@/types";

export default function Publications({ publications }: { publications: RemediationPublication[] }) {
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <GitPullRequest className="h-4 w-4 text-violet-300" /> Publications and verification
      </div>
      {publications.map((publication) => (
        <div key={publication.id} className="border-b border-slate-800 py-4 last:border-0">
          <div className="text-sm text-slate-200">{publication.repository}</div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs uppercase tracking-wider">
            <span className={cx("rounded-full px-2 py-1", statusTone(publication.status))}>{publication.status}</span>
            <span className={cx("rounded-full px-2 py-1", statusTone(publication.verification_status))}>
              {publication.verification_status || "awaiting verification"}
            </span>
          </div>
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
          {publication.findings_before !== null && publication.findings_after !== null && (
            <p className="mt-2 text-xs text-slate-500">
              Findings {publication.findings_before} → {publication.findings_after}
              {publication.scan_status ? ` · scan ${publication.scan_status}` : ""}
            </p>
          )}
        </div>
      ))}
      {!publications.length && <p className="text-sm text-slate-500">No publication yet.</p>}
    </div>
  );
}
