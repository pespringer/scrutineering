import { FileDown, KeyRound, ShieldCheck } from "lucide-react";
import type { SbomSummary } from "@/types";

const LINK = "inline-flex items-center gap-1.5 text-xs text-cyan-300 underline-offset-2 hover:underline";

/** Download links for a CycloneDX SBOM, its signature and the public key that verifies it. */
export default function SbomLink({ href, sbom }: { href: string; sbom: SbomSummary }) {
  const fingerprint = sbom.key_id?.replace(/^sha256:/, "");
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
      <a href={href} download title={`SHA-256 ${sbom.sha256}`} className={LINK}>
        <FileDown className="h-3.5 w-3.5" />
        SBOM (CycloneDX {sbom.spec_version}) · {sbom.components} components
      </a>
      {sbom.signed && fingerprint ? (
        <>
          <a href={`/api/scans/${sbom.scan_id}/sbom.sig`} download className={LINK}>
            <ShieldCheck className="h-3.5 w-3.5" />
            signature
          </a>
          <a href={`/api/signing-keys/${fingerprint}.pem`} download title={sbom.key_id ?? ""} className={LINK}>
            <KeyRound className="h-3.5 w-3.5" />
            public key
          </a>
        </>
      ) : (
        <span className="text-xs text-slate-500">unsigned</span>
      )}
    </div>
  );
}
