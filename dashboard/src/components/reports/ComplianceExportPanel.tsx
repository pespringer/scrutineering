"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Archive, FileDown } from "lucide-react";
import { useAsync } from "@/hooks/useAsync";
import { getJson, postJson } from "@/lib/http";
import { cx } from "@/lib/cx";
import type { ComplianceExport } from "@/types";

const FIELD = cx(
  "rounded-xl border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200",
  "outline-none focus:border-cyan-400/50",
);

function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function utcDay(value: string): string {
  return new Date(value).toLocaleDateString(undefined, { timeZone: "UTC" });
}

function size(bytes: number | null): string {
  if (!bytes) return "";
  return bytes > 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;
}

function ExportRow({ item }: { item: ComplianceExport }) {
  // `until` is exclusive in the API; show the last day included.
  const lastDay = new Date(new Date(item.until).getTime() - 24 * 3600 * 1000).toISOString();
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
      <span className="text-slate-300">
        {utcDay(item.since)} – {utcDay(lastDay)}
        <span className="ml-2 text-xs text-slate-500">requested {new Date(item.created_at).toLocaleString()}</span>
      </span>
      {item.status === "ready" ? (
        <a
          href={`/api/compliance/exports/${item.id}/download`}
          download
          title={item.sha256 ? `SHA-256 ${item.sha256}` : undefined}
          className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:underline"
        >
          <FileDown className="h-3.5 w-3.5" /> zip · {item.files} files · {size(item.size)}
        </a>
      ) : (
        <span className={cx("text-xs", item.status === "failed" ? "text-amber-200" : "text-slate-400")}>
          {item.status === "failed" ? `failed: ${item.error ?? "unknown error"}` : `${item.status}…`}
        </span>
      )}
    </li>
  );
}

/** Request a signed zip of a date range's evidence, SBOMs, reports, findings and audit log. */
export default function ComplianceExportPanel() {
  const today = new Date();
  const [since, setSince] = useState(isoDay(new Date(today.getTime() - 90 * 24 * 3600 * 1000)));
  const [until, setUntil] = useState(isoDay(today));
  const [notice, setNotice] = useState<string | null>(null);
  const load = useCallback(() => getJson<{ items: ComplianceExport[] }>("/api/compliance/exports"), []);
  const exports = useAsync(load);
  const items = exports.data?.items ?? [];
  const running = items.some((item) => item.status === "pending" || item.status === "building");
  const { reload } = exports;

  useEffect(() => {
    if (!running) return;
    const timer = setInterval(reload, 3000);
    return () => clearInterval(timer);
  }, [running, reload]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    try {
      await postJson("/api/compliance/exports", { since, until });
      reload();
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  return (
    <section className="panel mt-6 rounded-2xl p-5 sm:p-6">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Archive className="h-4 w-4 text-cyan-300" /> Compliance export
      </div>
      <p className="mb-4 max-w-3xl text-xs leading-5 text-slate-400">
        One zip for a range of UTC days: evidence bundles that ended in it, the SBOMs they cite, its reports, the
        findings open now plus those resolved in it, and the audit log. A signed <code>manifest.json</code> lists every
        file&apos;s SHA-256. Kept for 24 hours.
      </p>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-slate-400">
          From
          <input type="date" value={since} onChange={(e) => setSince(e.target.value)} className={`${FIELD} ml-2`} />
        </label>
        <label className="text-xs text-slate-400">
          To
          <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} className={`${FIELD} ml-2`} />
        </label>
        <button
          type="submit"
          disabled={running}
          className="rounded-xl bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {running ? "Building…" : "Export"}
        </button>
      </form>
      {notice && <p className="mt-3 text-xs text-amber-200">{notice}</p>}
      {exports.error && <p className="mt-3 text-xs text-amber-200">{exports.error}</p>}
      {items.length > 0 && (
        <ul className="mt-4 divide-y divide-slate-800/70">
          {items.map((item) => (
            <ExportRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </section>
  );
}
