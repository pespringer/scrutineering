import { FileDown } from "lucide-react";
import type { SbomSummary } from "@/types";

/** Download link for a CycloneDX SBOM, with its component count and SHA-256 on hover. */
export default function SbomLink({ href, sbom }: { href: string; sbom: SbomSummary }) {
  return (
    <a
      href={href}
      download
      title={`SHA-256 ${sbom.sha256}`}
      className="inline-flex items-center gap-1.5 text-xs text-cyan-300 underline-offset-2 hover:underline"
    >
      <FileDown className="h-3.5 w-3.5" />
      SBOM (CycloneDX {sbom.spec_version}) · {sbom.components} components
    </a>
  );
}
