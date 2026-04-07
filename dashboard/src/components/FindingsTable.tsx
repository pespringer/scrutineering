"use client";

import { useState, useMemo } from "react";
import SeverityBadge from "@/components/SeverityBadge";
import type { VulnerabilityFinding } from "@/types";

type SortKey = "cve_id" | "severity" | "package_name" | "package_version" | "first_seen";

export default function FindingsTable({ findings }: { findings: VulnerabilityFinding[] }) {
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
      <div className="flex items-center gap-3 mb-4">
        <label className="text-sm text-slate-400">Filter severity:</label>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-slate-900 text-slate-200 border border-slate-700 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="">All</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700/50">
              {cols.map((c) => (
                <th
                  key={c.key}
                  className="px-3 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer hover:text-slate-300 select-none whitespace-nowrap"
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
                <td colSpan={7} className="px-3 py-8 text-center text-slate-500">
                  No findings match your filter.
                </td>
              </tr>
            ) : sorted.map((f, i) => (
              <tr key={f.id || i} className="hover:bg-slate-800/30 transition-colors">
                <td className="px-3 py-3 font-mono text-slate-300 whitespace-nowrap">
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
                <td className="px-3 py-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="px-3 py-3 text-slate-300">{f.package_name}</td>
                <td className="px-3 py-3 font-mono text-slate-400">
                  {f.package_version || "-"}
                </td>
                <td className="px-3 py-3 font-mono text-xs text-slate-400 whitespace-nowrap">
                  {formatDate(f.first_seen)}
                </td>
                <td className="px-3 py-3 max-w-[250px] truncate text-slate-300" title={f.title || ""}>
                  {f.title || "-"}
                </td>
                <td className="px-3 py-3 font-mono text-sm whitespace-nowrap">
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
