import { Boxes } from "lucide-react";
import type { RemediationRecord } from "@/types";

/** What execution produced: the patch, the candidate image, and how its scan compared. */
export default function CandidatePanel({ remediation }: { remediation: RemediationRecord }) {
  const { patch, candidate_image: image, candidate_digest: digest, verification } = remediation;
  if (!patch && !image) return null;
  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Boxes className="h-4 w-4 text-cyan-300" /> Candidate image
      </div>
      {image && (
        <p className="mb-3 break-all font-mono text-xs text-slate-300">
          {image}
          {digest && <span className="block text-slate-500">{digest}</span>}
        </p>
      )}
      {verification && (
        <ul className="mb-4 space-y-1 text-sm text-slate-300">
          <li>
            Targeted findings still present:{" "}
            <span className={verification.still_present.length ? "text-rose-300" : "text-emerald-300"}>
              {verification.still_present.length} of {verification.targeted}
            </span>
          </li>
          <li>
            New critical or high findings:{" "}
            <span className={verification.new_critical_or_high.length ? "text-amber-300" : "text-emerald-300"}>
              {verification.new_critical_or_high.length}
            </span>
          </li>
          {verification.new_critical_or_high.slice(0, 20).map((item) => (
            <li key={`${item.cve_id}-${item.package_name}`} className="ml-4 font-mono text-xs text-amber-200">
              {item.severity} {item.cve_id} {item.package_name} {item.package_version}
            </li>
          ))}
          <li className="text-slate-500">{verification.candidate_findings} findings in the candidate overall</li>
        </ul>
      )}
      {patch && (
        <details>
          <summary className="cursor-pointer text-xs font-medium text-cyan-300">
            Patch{remediation.source_commit ? ` against ${remediation.source_commit.slice(0, 12)}` : ""}
          </summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded-xl bg-slate-950/70 p-3 text-xs text-slate-300">
            {patch}
          </pre>
        </details>
      )}
    </div>
  );
}
