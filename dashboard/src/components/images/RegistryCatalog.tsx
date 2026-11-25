"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Container, ExternalLink, Package } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import RegistryTagRow from "@/components/images/RegistryTagRow";
import { formatBytes } from "@/lib/bytes";
import { cx } from "@/lib/cx";
import type { RegistryInventory, RegistryRepository, RegistryTag } from "@/types";

type RowProps = { scanning: string | null; onScan: (item: RegistryTag) => void };

function Tags({ tags, scanning, onScan }: RowProps & { tags: RegistryTag[] }) {
  return tags.map((item) => (
    <RegistryTagRow key={item.image_name} item={item} scanning={scanning === item.image_name} onScan={onScan} />
  ));
}

/** One repository: its tags, with the candidates Scrutineering built folded away below them. */
function Repository({
  repository,
  tags,
  scanning,
  onScan,
}: RowProps & { repository: RegistryRepository; tags: RegistryTag[] }) {
  const [showCandidates, setShowCandidates] = useState(false);
  // Newest first: their tags end in the remediation's number.
  const candidates = tags
    .filter((item) => item.candidate)
    .sort((a, b) => b.tag.localeCompare(a.tag, undefined, { numeric: true }));
  const own = tags.filter((item) => !item.candidate);
  const Chevron = showCandidates ? ChevronDown : ChevronRight;
  return (
    <section className="border-b border-slate-800/80 last:border-b-0">
      <div
        className={cx(
          "flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-900/40",
          "px-5 py-3 lg:px-6",
        )}
      >
        <h3 className="flex min-w-0 items-center gap-2 text-sm font-semibold text-slate-200">
          <Container className="h-4 w-4 shrink-0 text-cyan-300" />
          <span className="truncate font-mono">{repository.name}</span>
        </h3>
        <span className="text-xs text-slate-400">
          {repository.tags} tag{repository.tags === 1 ? "" : "s"} · {formatBytes(repository.stored_bytes)} stored
        </span>
      </div>
      <div className="divide-y divide-slate-800/70">
        <Tags tags={own} scanning={scanning} onScan={onScan} />
        {candidates.length > 0 && (
          <button
            type="button"
            aria-expanded={showCandidates}
            onClick={() => setShowCandidates((value) => !value)}
            className={cx(
              "flex w-full items-center gap-2 px-5 py-3 text-left text-xs text-slate-400",
              "hover:bg-slate-800/20 hover:text-slate-200 lg:px-6",
            )}
          >
            <Chevron className="h-3.5 w-3.5" />
            {candidates.length} candidate{candidates.length === 1 ? "" : "s"} built by remediations
          </button>
        )}
        {showCandidates && <Tags tags={candidates} scanning={scanning} onScan={onScan} />}
      </div>
    </section>
  );
}

/** Every tag in the bundled registry, by repository. See docs/design/registry-management.md. */
export default function RegistryCatalog({
  inventory,
  scanning,
  onScan,
}: RowProps & {
  inventory: RegistryInventory;
}) {
  return (
    <section className="panel mb-8 overflow-hidden rounded-2xl">
      <div
        className={cx(
          "flex flex-col gap-2 border-b border-slate-800/80",
          "px-5 py-5 sm:flex-row sm:items-center sm:justify-between",
          "sm:px-6",
        )}
      >
        <div>
          <div className="eyebrow mb-2">Registry catalog</div>
          <div className="text-sm text-slate-400">
            Sizes are compressed, as the registry stores them. Layers shared by several images are stored once.
          </div>
        </div>
        <a
          href={inventory.registry.url}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 text-xs text-cyan-300 hover:text-cyan-200"
        >
          Open registry API <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
      {inventory.repositories.map((repository) => (
        <Repository
          key={repository.name}
          repository={repository}
          tags={inventory.tags.filter((item) => item.repository === repository.name)}
          scanning={scanning}
          onScan={onScan}
        />
      ))}
      {!inventory.tags.length && (
        <EmptyState
          icon={Package}
          title="Registry is empty"
          description={`Push an image to ${inventory.registry.host}, then refresh this page.`}
        />
      )}
    </section>
  );
}
