"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Container, ExternalLink, Package } from "lucide-react";
import EmptyState from "@/components/EmptyState";
import RegistryDelete, { DeleteResults } from "@/components/images/RegistryDelete";
import RegistryTagRow from "@/components/images/RegistryTagRow";
import { can, usePermissions } from "@/hooks/usePermissions";
import { formatBytes } from "@/lib/bytes";
import { cx } from "@/lib/cx";
import type { RegistryDeleteResult, RegistryInventory, RegistryRepository, RegistryTag } from "@/types";

type ScanProps = { scanning: string | null; onScan: (item: RegistryTag) => void };

/** `selection` is null when the viewer can't delete tags. */
type RowProps = ScanProps & {
  selection: ReadonlySet<string> | null;
  onSelect: (names: string[], selected: boolean) => void;
};

function Tags({ tags, scanning, onScan, selection, onSelect }: RowProps & { tags: RegistryTag[] }) {
  return tags.map((item) => (
    <RegistryTagRow
      key={item.image_name}
      item={item}
      scanning={scanning === item.image_name}
      onScan={onScan}
      selected={selection ? selection.has(item.image_name) : null}
      onSelect={(selected) => onSelect([item.image_name], selected)}
    />
  ));
}

/** The line that unfolds the candidates, and selects them all. */
function CandidatesLine({
  candidates,
  open,
  onToggle,
  selection,
  onSelect,
}: Pick<RowProps, "selection" | "onSelect"> & { candidates: RegistryTag[]; open: boolean; onToggle: () => void }) {
  const Chevron = open ? ChevronDown : ChevronRight;
  const names = candidates.filter((item) => item.digest).map((item) => item.image_name);
  const all = selection !== null && names.length > 0 && names.every((name) => selection.has(name));
  return (
    <div className="flex items-center justify-between gap-3 px-5 text-xs text-slate-400 lg:px-6">
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className="flex flex-1 items-center gap-2 py-3 text-left hover:text-slate-200"
      >
        <Chevron className="h-3.5 w-3.5" />
        {candidates.length} candidate{candidates.length === 1 ? "" : "s"} built by remediations
      </button>
      {open && selection && (
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            checked={all}
            onChange={(event) => onSelect(names, event.target.checked)}
            className="accent-rose-400"
          />
          Select all
        </label>
      )}
    </div>
  );
}

/** One repository: its tags, with the candidates Scrutineering built folded away below them. */
function Repository({ repository, tags, ...row }: RowProps & { repository: RegistryRepository; tags: RegistryTag[] }) {
  const [showCandidates, setShowCandidates] = useState(false);
  // Newest first: their tags end in the remediation's number.
  const candidates = tags
    .filter((item) => item.candidate)
    .sort((a, b) => b.tag.localeCompare(a.tag, undefined, { numeric: true }));
  const own = tags.filter((item) => !item.candidate);
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
        <Tags tags={own} {...row} />
        {candidates.length > 0 && (
          <CandidatesLine
            candidates={candidates}
            open={showCandidates}
            onToggle={() => setShowCandidates((value) => !value)}
            selection={row.selection}
            onSelect={row.onSelect}
          />
        )}
        {showCandidates && <Tags tags={candidates} {...row} />}
      </div>
    </section>
  );
}

/** Every tag in the bundled registry, by repository. See docs/design/registry-management.md. */
export default function RegistryCatalog({
  inventory,
  scanning,
  onScan,
  onChanged,
}: ScanProps & {
  inventory: RegistryInventory;
  onChanged: () => void;
}) {
  const mayDelete = can(usePermissions(), "registry.delete");
  const [selection, setSelection] = useState<ReadonlySet<string>>(new Set());
  const [results, setResults] = useState<RegistryDeleteResult[]>([]);
  const selected = inventory.tags.filter((item) => item.digest && selection.has(item.image_name));

  function select(names: string[], on: boolean) {
    setSelection((previous) => {
      const next = new Set(previous);
      names.forEach((name) => (on ? next.add(name) : next.delete(name)));
      return next;
    });
  }

  function finish(outcome: RegistryDeleteResult[]) {
    setResults(outcome);
    setSelection(new Set());
    onChanged();
  }

  return (
    <section className="panel mb-8 overflow-clip rounded-2xl">
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
      {results.length > 0 && <DeleteResults results={results} onDismiss={() => setResults([])} />}
      {inventory.repositories.map((repository) => (
        <Repository
          key={repository.name}
          repository={repository}
          tags={inventory.tags.filter((item) => item.repository === repository.name)}
          scanning={scanning}
          onScan={onScan}
          selection={mayDelete ? selection : null}
          onSelect={select}
        />
      ))}
      {!inventory.tags.length && (
        <EmptyState
          icon={Package}
          title="Registry is empty"
          description={`Push an image to ${inventory.registry.host}, then refresh this page.`}
        />
      )}
      {mayDelete && selected.length > 0 && (
        <RegistryDelete selected={selected} onClear={() => setSelection(new Set())} onDone={finish} />
      )}
    </section>
  );
}
