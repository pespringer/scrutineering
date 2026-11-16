"use client";

import { FormEvent, useState } from "react";
import { Play, Search } from "lucide-react";
import { cx } from "@/lib/cx";
import { postJson } from "@/lib/http";

type Queued = { scan_id: string; image_name: string };

/** Queue a scan for one container image reference. */
export default function ScanForm({ onQueued }: { onQueued: (scan: Queued) => void }) {
  const [imageName, setImageName] = useState("");
  const [priority, setPriority] = useState("normal");
  const [starting, setStarting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!imageName.trim()) return;
    setStarting(true);
    setNotice(null);
    try {
      const queued = await postJson<Queued>("/api/scans", { image_name: imageName.trim(), priority });
      setImageName("");
      setNotice(`Scan queued for ${queued.image_name}.`);
      onQueued(queued);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to queue scan.");
    } finally {
      setStarting(false);
    }
  }

  return (
    <form onSubmit={submit} className="panel mb-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-4">
        <div className="eyebrow mb-2">Scan control</div>
        <h2 className="text-lg font-semibold text-white">Run a targeted scan</h2>
      </div>
      <div className="flex flex-col gap-3 lg:flex-row">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
          <input
            id="scan-image"
            aria-label="Image reference"
            value={imageName}
            onChange={(e) => setImageName(e.target.value)}
            placeholder="nginx:1.27 or registry:5000/team/app:1.0"
            className={cx(
              "w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-sm text-slate-200",
              "outline-none placeholder:text-slate-600 focus:border-cyan-400/50",
            )}
          />
        </div>
        <select
          id="scan-priority"
          aria-label="Priority"
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
          className="rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 text-sm text-slate-300 outline-none"
        >
          <option value="low">Low priority</option>
          <option value="normal">Normal priority</option>
          <option value="high">High priority</option>
        </select>
        <button
          disabled={starting || !imageName.trim()}
          className={cx(
            "inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold",
            "text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50",
          )}
        >
          <Play className="h-4 w-4" />
          {starting ? "Queueing…" : "Start scan"}
        </button>
      </div>
      {notice && <p className="mt-3 text-sm text-cyan-200">{notice}</p>}
    </form>
  );
}
