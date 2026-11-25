"use client";

import { useCallback } from "react";
import { useAsync } from "@/hooks/useAsync";
import { formatBytes } from "@/lib/bytes";
import type { RegistryImage, RegistryTagDetail } from "@/types";

async function loadDetail(repository: string, tag: string): Promise<RegistryTagDetail> {
  const query = new URLSearchParams({ repository, tag });
  const response = await fetch(`/api/registry/tags/detail?${query}`, { cache: "no-store" });
  if (response.ok) return response.json();
  const body = await response.json().catch(() => ({}));
  if (response.status === 404) throw new Error("This tag is no longer in the registry. Refresh the page.");
  throw new Error(typeof body.detail === "string" ? body.detail : "This image can't be read.");
}

function Fact({ label, value }: { label: string; value: string | null }) {
  if (!value) return null;
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-words font-mono text-xs text-slate-300">{value}</dd>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details className="mt-3 rounded-lg border border-slate-800 px-3 py-2">
      <summary className="cursor-pointer text-xs text-slate-300">{title}</summary>
      <div className="mt-2 max-h-80 overflow-auto">{children}</div>
    </details>
  );
}

function ImageContents({ image }: { image: RegistryImage }) {
  const labels = Object.entries(image.labels);
  return (
    <div className="border-t border-slate-800/80 py-4 first:border-t-0">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-sm font-semibold text-slate-200">{image.platform}</span>
        <span className="text-xs text-slate-400">{formatBytes(image.size)} compressed</span>
        <span className="break-all font-mono text-[11px] text-slate-500">{image.digest}</span>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <Fact label="Built" value={image.created && new Date(image.created).toLocaleString()} />
        <Fact label="User" value={image.user ?? "root (not set)"} />
        <Fact label="Working directory" value={image.working_dir} />
        <Fact label="Entrypoint" value={image.entrypoint.join(" ")} />
        <Fact label="Command" value={image.command.join(" ")} />
        <Fact label="Exposed ports" value={image.exposed_ports.join(", ")} />
      </dl>
      <Section title={`Layers (${image.layers.length})`}>
        <ol className="space-y-1 font-mono text-[11px] text-slate-400">
          {image.layers.map((layer, index) => (
            <li key={index} className="flex justify-between gap-4">
              <span className="break-all">{layer.digest ?? "unknown"}</span>
              <span className="shrink-0 text-slate-300">{formatBytes(layer.size)}</span>
            </li>
          ))}
        </ol>
      </Section>
      {labels.length > 0 && (
        <Section title={`Labels (${labels.length})`}>
          <dl className="space-y-1 text-[11px]">
            {labels.map(([key, value]) => (
              <div key={key} className="break-words font-mono text-slate-400">
                <dt className="inline text-slate-300">{key}</dt>: <dd className="inline">{value}</dd>
              </div>
            ))}
          </dl>
        </Section>
      )}
      {image.history.length > 0 && (
        <Section title={`Build history (${image.history.length})`}>
          <p className="mb-2 text-[11px] text-slate-500">Environment values and build arguments are hidden.</p>
          <ol className="space-y-1.5 font-mono text-[11px] text-slate-400">
            {image.history.map((entry, index) => (
              <li key={index} className="whitespace-pre-wrap break-words">
                {entry.command || "(no command recorded)"}
              </li>
            ))}
          </ol>
        </Section>
      )}
    </div>
  );
}

/** What one tag holds, per platform. The text comes from whoever built the image, so it's only ever text. */
export default function RegistryTagDetails({
  repository,
  tag,
  digest,
}: {
  repository: string;
  tag: string;
  digest: string;
}) {
  const load = useCallback(() => loadDetail(repository, tag), [repository, tag]);
  const { data, error, loading } = useAsync(load);
  return (
    <div className="border-t border-slate-800/80 bg-slate-950/30 px-5 py-2 lg:px-6">
      {error && <p className="py-3 text-xs text-amber-200">{error}</p>}
      {loading && !data && <p className="py-3 text-xs text-slate-500">Reading the image…</p>}
      {data && data.digest !== digest && (
        <p className="pt-3 text-xs text-amber-200">This tag was pushed again since the list was loaded.</p>
      )}
      {data && data.images.length > 1 && <Fact label="Index digest" value={data.digest} />}
      {data?.images.map((image, index) => <ImageContents key={`${image.digest}-${index}`} image={image} />)}
      {data && data.attestations > 0 && (
        <p className="pb-3 text-xs text-slate-500">
          {data.attestations} build attestation{data.attestations === 1 ? "" : "s"} stored with it.
        </p>
      )}
    </div>
  );
}
