"use client";

import { useState } from "react";
import { Archive, RotateCcw, XCircle } from "lucide-react";
import { postJson } from "@/lib/http";

type Action = "bulk-cancel" | "bulk-retry" | "bulk-archive";

const BUTTONS: Array<{ action: Action; label: string; icon: typeof XCircle; tone: string }> = [
  { action: "bulk-cancel", label: "Cancel", icon: XCircle, tone: "border-rose-400/20 text-rose-300" },
  { action: "bulk-retry", label: "Retry", icon: RotateCcw, tone: "border-cyan-400/20 text-cyan-300" },
  { action: "bulk-archive", label: "Archive", icon: Archive, tone: "border-slate-600 text-slate-300" },
];

/** Cancel, retry, or archive the selected scans. */
export default function BulkScanActions({ selected, onDone }: { selected: string[]; onDone: (msg: string) => void }) {
  const [busy, setBusy] = useState(false);

  async function run(action: Action) {
    setBusy(true);
    try {
      const result = await postJson<{ count?: number }>(`/api/scans/${action}`, { ids: selected });
      onDone(`${result.count || 0} scan(s) updated.`);
    } catch {
      onDone("Bulk scan action failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 bg-slate-950/30 px-5 py-3 text-xs">
      <span className="mr-2 text-slate-400">{selected.length} selected</span>
      {BUTTONS.map(({ action, label, icon: Icon, tone }) => (
        <button
          key={action}
          disabled={busy}
          onClick={() => run(action)}
          className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 ${tone}`}
        >
          <Icon className="h-3.5 w-3.5" /> {label}
        </button>
      ))}
    </div>
  );
}
