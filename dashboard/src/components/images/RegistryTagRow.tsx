"use client";

import Link from "next/link";
import { useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, Layers, Package, Play } from "lucide-react";
import RegistryTagDetails from "@/components/images/RegistryTagDetails";
import { formatBytes } from "@/lib/bytes";
import { cx } from "@/lib/cx";
import type { RegistryCandidate, RegistryTag } from "@/types";

const STATUS: Record<RegistryTag["security_status"], { label: string; tone: string }> = {
  clean: { label: "Clean", tone: "bg-emerald-400/10 text-emerald-200" },
  issues_found: { label: "Issues found", tone: "bg-rose-400/10 text-rose-200" },
  scan_failed: { label: "Scan failed", tone: "bg-rose-400/10 text-rose-200" },
  scanning: { label: "Scanning", tone: "bg-cyan-400/10 text-cyan-200" },
  not_scanned: { label: "Not scanned", tone: "bg-amber-400/10 text-amber-200" },
};

/** Which remediation built a candidate, when the records say so (and the viewer may see remediations). */
function candidateLabel(candidate: RegistryCandidate): string {
  if (candidate.unmatched) return "candidate · no matching remediation, so not cleaned up";
  if (!candidate.remediation_id || !candidate.status) return "candidate";
  return `remediation ${candidate.remediation_id} · ${candidate.status.replace(/_/g, " ")}`;
}

/** What the registry says about the tag: digest, size, platforms, and what shares its image. */
function Facts({ item }: { item: RegistryTag }) {
  return (
    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500">
      <span title={item.digest ?? undefined} className="font-mono">
        {item.digest ? item.digest.slice(0, 19) : "digest unavailable"}
      </span>
      {item.size !== null && <span className="text-slate-300">{formatBytes(item.size)}</span>}
      {item.platforms.length > 0 && <span>{item.platforms.map((entry) => entry.platform).join(", ")}</span>}
      {item.shared_count > 0 && (
        <span title="Other tags in this repository that point to the same image">
          same image as {item.shared_count} other tag{item.shared_count === 1 ? "" : "s"}
        </span>
      )}
      {item.candidate && <span>{candidateLabel(item.candidate)}</span>}
      <span>{item.last_scan_at ? `Scanned ${new Date(item.last_scan_at).toLocaleString()}` : "Never scanned"}</span>
      {item.error && <span className="text-amber-200">Can&apos;t be read: {item.error}</span>}
    </div>
  );
}

export default function RegistryTagRow({
  item,
  scanning,
  onScan,
  selected,
  onSelect,
}: {
  item: RegistryTag;
  scanning: boolean;
  onScan: (item: RegistryTag) => void;
  /** Whether it's selected for deletion; null when the viewer can't delete tags. */
  selected: boolean | null;
  onSelect: (selected: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const status = STATUS[item.security_status];
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <div>
      <div
        className={cx(
          "flex flex-col gap-4 p-5 transition hover:bg-slate-800/20 lg:flex-row lg:items-center",
          "lg:justify-between lg:px-6",
        )}
      >
        <div className="flex min-w-0 items-center gap-4">
          {selected !== null && (
            <input
              type="checkbox"
              aria-label={`Select ${item.image_name}`}
              checked={selected}
              disabled={!item.digest}
              onChange={(event) => onSelect(event.target.checked)}
              className="shrink-0 accent-rose-400"
            />
          )}
          <div
            className={cx(
              "flex h-10 w-10 shrink-0 items-center",
              "justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10",
              "text-cyan-300",
            )}
          >
            <Package className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <div className="truncate font-mono text-sm text-slate-200">{item.tag}</div>
            <Facts item={item} />
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-3 lg:justify-end">
          <span className={cx("rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider", status.tone)}>
            {status.label}
          </span>
          {item.open_findings > 0 && (
            <span className="text-xs text-rose-200">
              {item.open_findings} open · {item.critical_count} critical · {item.high_count} high
            </span>
          )}
          {item.image_id ? (
            <Link
              href={`/images/${item.image_id}`}
              className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200"
            >
              Findings <ExternalLink className="h-3.5 w-3.5" />
            </Link>
          ) : null}
          <button
            type="button"
            aria-expanded={open}
            aria-label={`Contents of ${item.image_name}`}
            disabled={!item.digest}
            onClick={() => setOpen((value) => !value)}
            className={cx(
              "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300",
              "hover:text-white disabled:cursor-not-allowed disabled:opacity-40",
            )}
          >
            <Layers className="h-3.5 w-3.5" /> Contents <Chevron className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            disabled={scanning || item.security_status === "scanning"}
            onClick={() => onScan(item)}
            className={cx(
              "inline-flex items-center gap-1 rounded-lg border border-violet-400/30 px-3 py-2 text-xs",
              "text-violet-100 disabled:cursor-not-allowed disabled:opacity-40",
            )}
          >
            <Play className="h-3.5 w-3.5" />{" "}
            {item.security_status === "scanning" ? "Scanning" : item.image_id ? "Rescan" : "Scan image"}
          </button>
        </div>
      </div>
      {open && item.digest && (
        <RegistryTagDetails key={item.digest} repository={item.repository} tag={item.tag} digest={item.digest} />
      )}
    </div>
  );
}
