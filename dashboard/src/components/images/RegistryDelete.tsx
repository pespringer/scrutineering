"use client";

import { useState } from "react";
import { Trash2 } from "lucide-react";
import { cx } from "@/lib/cx";
import type { RegistryDeleteResult, RegistryTag } from "@/types";

/** The most tags one request may delete (src/api/schemas.py). */
export const MAX_DELETE = 100;

async function deleteTags(tags: RegistryTag[]): Promise<RegistryDeleteResult[]> {
  const items = tags.map(({ repository, tag, digest }) => ({ repository, tag, digest }));
  const response = await fetch("/api/registry/tags/delete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ items }),
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 403) throw new Error("Your role can't delete tags.");
  if (!response.ok) throw new Error("The tags couldn't be deleted. Refresh to see what's left.");
  return body.results;
}

/** What happened to each tag: how many went, and why the others didn't. */
export function DeleteResults({ results, onDismiss }: { results: RegistryDeleteResult[]; onDismiss: () => void }) {
  const deleted = results.filter((item) => item.deleted).length;
  const notes = results.filter((item) => item.reason);
  return (
    <div
      role="status"
      className="border-b border-slate-800/80 bg-slate-950/40 px-5 py-4 text-sm text-slate-200 lg:px-6"
    >
      <div className="flex items-center justify-between gap-4">
        <span>
          {deleted} of {results.length} tag{results.length === 1 ? "" : "s"} deleted.
        </span>
        <button type="button" onClick={onDismiss} className="text-xs text-slate-400 hover:text-white">
          Dismiss
        </button>
      </div>
      {notes.length > 0 && (
        <ul className="mt-2 max-h-60 space-y-1 overflow-auto text-xs text-amber-200">
          {notes.map((item) => (
            <li key={`${item.repository}:${item.tag}`}>
              <span className="font-mono">
                {item.repository}:{item.tag}
              </span>
              : {item.reason}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** The selected tags, and the step that confirms deleting them. The server decides what may go. */
export default function RegistryDelete({
  selected,
  onClear,
  onDone,
}: {
  selected: RegistryTag[];
  onClear: () => void;
  onDone: (results: RegistryDeleteResult[]) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const count = `${selected.length} tag${selected.length === 1 ? "" : "s"}`;
  const tooMany = selected.length > MAX_DELETE;

  async function confirm() {
    setBusy(true);
    setError("");
    try {
      onDone(await deleteTags(selected));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The tags couldn't be deleted.");
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  return (
    <div
      className={cx(
        "sticky bottom-0 z-10 border-t border-rose-400/20 bg-[#130f18] px-5 py-4",
        "text-sm text-slate-200 lg:px-6",
      )}
    >
      {confirming && (
        <div className="mb-3">
          <p className="font-semibold text-white">Delete {count} from the registry? This can&apos;t be undone.</p>
          <ul className="mt-2 max-h-40 overflow-auto font-mono text-xs text-slate-300">
            {selected.map((item) => (
              <li key={item.image_name}>
                {item.repository}:{item.tag}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Other tags that share an image are kept, and so are scans, findings and evidence. Scheduled scans of the
            deleted tags stop. Tags that a remediation, a scan or a running container needs are refused.
          </p>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-slate-400">
          {tooMany ? `${count} selected. Delete up to ${MAX_DELETE} at a time.` : `${count} selected`}
        </span>
        <div className="flex gap-3">
          <button
            type="button"
            disabled={busy}
            onClick={confirming ? () => setConfirming(false) : onClear}
            className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:text-white"
          >
            {confirming ? "Keep them" : "Clear selection"}
          </button>
          <button
            type="button"
            disabled={busy || tooMany}
            onClick={confirming ? confirm : () => setConfirming(true)}
            className={cx(
              "inline-flex items-center gap-1 rounded-lg border border-rose-400/40 bg-rose-400/10 px-3 py-2 text-xs",
              "text-rose-100 disabled:cursor-not-allowed disabled:opacity-40",
            )}
          >
            <Trash2 className="h-3.5 w-3.5" /> {busy ? "Deleting…" : confirming ? `Delete ${count}` : "Delete…"}
          </button>
        </div>
      </div>
      {error && <p className="mt-2 text-xs text-rose-200">{error}</p>}
    </div>
  );
}
