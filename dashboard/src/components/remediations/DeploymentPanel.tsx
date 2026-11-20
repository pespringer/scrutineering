import { Boxes } from "lucide-react";
import Link from "next/link";
import type { RemediationDeployment } from "@/types";

function summary(deployment: RemediationDeployment): string {
  if (deployment.containers === 0) return "No container of this image is running.";
  if (deployment.fixed === null) {
    const running = `${deployment.containers} container(s) running`;
    return `${running}; the fix was scanned by tag, so their builds can't be compared.`;
  }
  return `${deployment.fixed} of ${deployment.containers} container(s) run the fixed build.`;
}

/** For a completed remediation: whether the running containers have picked up the fix. */
export default function DeploymentPanel({
  imageId,
  deployment,
}: {
  imageId: number;
  deployment?: RemediationDeployment | null;
}) {
  if (!deployment) return null;
  const pending = deployment.not_fixed.length;
  return (
    <section className="panel rounded-2xl p-5">
      <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-200">
        <Boxes className="h-4 w-4 text-cyan-300" /> Deployed
      </div>
      <p className={pending ? "text-xs leading-5 text-amber-200" : "text-xs leading-5 text-slate-400"}>
        {summary(deployment)}
      </p>
      {pending > 0 && (
        <p className="mt-2 text-xs leading-5 text-slate-400">
          Still on an older build: <span className="font-mono text-slate-300">{deployment.not_fixed.join(", ")}</span>.
          Recreate them from the current tag.{" "}
          <Link href={`/images/${imageId}`} className="text-cyan-300 hover:text-cyan-200">
            See containers
          </Link>
        </p>
      )}
    </section>
  );
}
