"use client";

import { useState, useMemo } from "react";
import SeverityBadge from "@/components/SeverityBadge";
import type { VulnerabilityFinding } from "@/types";

type SortKey = "cve_id" | "severity" | "package_name" | "package_version" | "first_seen";

export default function FindingsTable({ findings, selectable = false, selected = [], onSelect }: { findings: VulnerabilityFinding[]; selectable?: boolean; selected?: number[]; onSelect?: (id: number, checked: boolean) => void }) {
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filterSeverity, setFilterSeverity] = useState<string>("");

  const filtered = useMemo(
    () => findings.filter((f) => !filterSeverity || f.severity === filterSeverity),
    [findings, filterSeverity]
  );

  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      if (sortKey === "severity") {
        const diff = (severityOrder[a.severity ?? "UNKNOWN"] ?? 5) - (severityOrder[b.severity ?? "UNKNOWN"] ?? 5);
        return sortDir === "asc" ? diff : -diff;
      }
      const aVal = String(a[sortKey] ?? "");
      const bVal = String(b[sortKey] ?? "");
      return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const cols: { key: SortKey; label: string }[] = [
    { key: "cve_id", label: "CVE" },
    { key: "severity", label: "Severity" },
    { key: "package_name", label: "Package" },
    { key: "package_version", label: "Version" },
    { key: "first_seen", label: "First Seen" },
  ];

  return (
    <div>
      {/* Filter */}
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div><div className="eyebrow mb-1">Findings</div><p className="text-sm text-slate-400">Sort and filter the issues discovered in this image.</p></div>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          aria-label="Filter findings by severity"
          className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/10"
        >
          <option value="">All</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-sm">
          <thead className="bg-slate-900/40">
            <tr className="border-b border-slate-700/50">
              {selectable && <th className="w-10 px-3 py-3" />}
              {cols.map((c) => (
                <th
                  key={c.key}
                  className="cursor-pointer whitespace-nowrap px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600 transition hover:text-slate-300"
                  onClick={() => handleSort(c.key)}
                >
                  {c.label}
                  {sortKey === c.key && (
                    <span className="ml-1 text-blue-400">{sortDir === "asc" ? " ↑" : " ↓"}</span>
                  )}
                </th>
              ))}
              <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Title</th>
              <th className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={selectable ? 8 : 7} className="px-3 py-8 text-center text-slate-500">
                  No findings match your filter.
                </td>
              </tr>
            ) : sorted.map((f, i) => (
              <tr key={f.id || i} className="transition-colors hover:bg-cyan-400/[0.03]">
                {selectable && <td className="px-3 py-4"><input aria-label={`Select finding ${f.cve_id || f.id}`} type="checkbox" checked={selected.includes(f.id)} onChange={(event) => onSelect?.(f.id, event.target.checked)} className="h-4 w-4 accent-cyan-400" /></td>}
                <td className="whitespace-nowrap px-3 py-4 font-mono text-slate-300">
                  {f.cve_id ? (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      {f.cve_id}
                    </a>
                  ) : (
                    <span className="text-slate-600">-</span>
                  )}
                </td>
                <td className="px-3 py-4">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="px-3 py-4 font-medium text-slate-300">{f.package_name}</td>
                <td className="px-3 py-4 font-mono text-slate-400">
                  {f.package_version || "-"}
                </td>
                <td className="whitespace-nowrap px-3 py-4 font-mono text-xs text-slate-500">
                  {formatDate(f.first_seen)}
                </td>
                <td className="max-w-[250px] truncate px-3 py-4 text-slate-300" title={f.title || ""}>
                  {f.title || "-"}
                </td>
                <td className="whitespace-nowrap px-3 py-4 font-mono text-sm">
                  {f.fixed_version ? (
                    <span className="text-emerald-400">{f.fixed_version}</span>
                  ) : (
                    <span className="text-slate-600">-</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatDate(d: string) {
  try { return new Date(d).toLocaleDateString(); } catch { return d; }
}
