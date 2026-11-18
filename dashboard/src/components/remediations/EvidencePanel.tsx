import { FileDown, KeyRound, ShieldCheck } from "lucide-react";
import type { EvidenceSummary } from "@/types";

const VERIFY_BOX = "overflow-x-auto rounded-lg bg-slate-950/60 p-3 font-mono text-[11px] leading-5 text-slate-400";
const LINK = "inline-flex items-center gap-1.5 text-xs text-cyan-300 underline-offset-2 hover:underline";

/** The remediation's signed evidence bundle (docs/design/sbom-evidence.md), once it has ended. */
export default function EvidencePanel({ id, evidence }: { id: number; evidence?: EvidenceSummary | null }) {
  const fingerprint = evidence?.key_id?.replace(/^sha256:/, "");
  return (
    <section className="panel rounded-2xl p-5">
      <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-200">
        <ShieldCheck className="h-4 w-4 text-cyan-300" /> Evidence
      </div>
      {!evidence ? (
        <p className="text-xs leading-5 text-slate-500">
          Built within a minute of the remediation completing or failing: targets, plan, patch, candidate and its
          verification, the pull request, the scans before and after, and the timeline, signed.
        </p>
      ) : (
        <div className="space-y-3">
          <p className="text-xs leading-5 text-slate-400">
            Frozen when it {evidence.outcome === "completed" ? "completed" : "failed"}
            {evidence.created_at ? `, ${new Date(evidence.created_at).toLocaleString()}` : ""}.
          </p>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            <a href={`/api/remediations/${id}/evidence`} download title={`SHA-256 ${evidence.sha256}`} className={LINK}>
              <FileDown className="h-3.5 w-3.5" /> evidence.json
            </a>
            {evidence.signed && fingerprint ? (
              <>
                <a href={`/api/remediations/${id}/evidence.sig`} download className={LINK}>
                  <ShieldCheck className="h-3.5 w-3.5" /> signature
                </a>
                <a href={`/api/signing-keys/${fingerprint}.pem`} download className={LINK}>
                  <KeyRound className="h-3.5 w-3.5" /> public key
                </a>
              </>
            ) : (
              <span className="text-xs text-slate-500">unsigned</span>
            )}
          </div>
          {evidence.signed && (
            <pre className={VERIFY_BOX}>
              {`openssl dgst -sha256 -verify key.pem \\\n  -signature <(base64 -d evidence.json.sig) evidence.json`}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}
