"use client";

import { useCallback } from "react";
import { Boxes } from "lucide-react";
import { useAsync } from "@/hooks/useAsync";
import { cx } from "@/lib/cx";
import type { DeploymentContainer, ImageDeployments } from "@/types";

const STATE_TONE: Record<DeploymentContainer["state"], string> = {
  current: "bg-emerald-400/10 text-emerald-200",
  stale: "bg-amber-400/10 text-amber-200",
  unknown: "bg-slate-500/10 text-slate-300",
};

const STATE_HELP: Record<DeploymentContainer["state"], string> = {
  current: "Runs the build of the latest scan",
  stale: "Runs an older build than the latest scan: recreate it from the current tag",
  unknown: "The latest scan was made by tag, without a digest, so the build can't be compared",
};

async function loadDeployments(imageId: number): Promise<ImageDeployments> {
  const response = await fetch(`/api/images/${imageId}/deployments`, { cache: "no-store" });
  if (!response.ok) throw new Error(`containers unavailable (${response.status})`);
  return response.json();
}

function shortDigest(digests: string[]): string {
  return digests[0] ? digests[0].replace(/^sha256:/, "").slice(0, 12) : "no digest";
}

function ContainerRow({ container }: { container: DeploymentContainer }) {
  const gone = Boolean(container.gone_at);
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-2">
      <div className="min-w-0">
        <div className={cx("truncate font-mono text-sm", gone ? "text-slate-500" : "text-slate-200")}>
          {container.name || container.container_id.slice(0, 12)}
        </div>
        <div className="text-[11px] text-slate-500" title={container.running_digests.join("\n")}>
          build {shortDigest(container.running_digests)}
          {container.started_at && ` · started ${new Date(container.started_at).toLocaleString()}`}
          {gone && ` · gone ${new Date(container.gone_at as string).toLocaleString()}`}
        </div>
      </div>
      <span
        title={STATE_HELP[container.state]}
        className={cx(
          "rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
          gone ? "bg-slate-500/10 text-slate-400" : STATE_TONE[container.state],
        )}
      >
        {gone ? "gone" : container.state}
      </span>
    </li>
  );
}

/** The image's containers that runtime discovery sees, each current or stale.
 * See docs/design/deployment-observation.md. */
export default function DeploymentsPanel({ imageId }: { imageId: number }) {
  const load = useCallback(() => loadDeployments(imageId), [imageId]);
  const { data, error } = useAsync(load);
  const containers = data?.containers ?? [];
  const gone = data?.gone ?? [];
  const stale = containers.filter((container) => container.state === "stale").length;
  return (
    <section className="panel mb-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Boxes className="h-4 w-4 text-cyan-300" /> Containers
        </div>
        {containers.length > 0 && (
          <span className="text-xs text-slate-400">
            {containers.length} running{stale ? ` · ${stale} stale` : ""}
          </span>
        )}
      </div>
      {error && <p className="text-xs text-amber-200">{error}</p>}
      {!error && data && containers.length === 0 && gone.length === 0 && (
        <p className="text-xs leading-5 text-slate-500">
          Runtime discovery hasn&apos;t seen a container of this image in the last 30 minutes.
        </p>
      )}
      {containers.length + gone.length > 0 && (
        <ul className="divide-y divide-slate-800/80">
          {[...containers, ...gone].map((container) => (
            <ContainerRow key={container.container_id} container={container} />
          ))}
        </ul>
      )}
    </section>
  );
}
