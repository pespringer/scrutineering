"use client";

import { SeverityIcon } from "./severity-icon";

export function StatCard({
  title,
  value,
  subtitle,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <dt className="text-sm text-gray-400 mb-1">{title}</dt>
      <dd className="text-2xl font-bold">{value}</dd>
      {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const colorMap: Record<string, string> = {
    CRITICAL: "bg-red-950 text-red-400 border-red-800",
    HIGH: "bg-orange-950 text-orange-400 border-orange-800",
    MEDIUM: "bg-yellow-950 text-yellow-400 border-yellow-800",
    LOW: "bg-blue-950 text-blue-400 border-blue-800",
    UNKNOWN: "bg-gray-800 text-gray-400 border-gray-700",
  };
  const cls = colorMap[severity] || colorMap.UNKNOWN;
  return (
    <span className={`inline-flex items-center gap-1 text-xs border rounded-full px-2 py-0.5 font-medium ${cls}`}>
      {severity}
    </span>
  );
}

export function FindingsTable({ findings }: { findings: any[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        No findings to display.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-400 uppercase text-xs">
            <th className="text-left py-3 px-2">Severity</th>
            <th className="text-left py-3 px-2">CVE</th>
            <th className="text-left py-3 px-2">Title</th>
            <th className="text-left py-3 px-2">Package</th>
            <th className="text-left py-3 px-2">Version</th>
            <th className="text-left py-3 px-2">Fixed</th>
            <th className="text-left py-3 px-2">First Seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/50">
          {findings.map((f) => (
            <tr key={f.id} className="hover:bg-gray-900/50">
              <td className="py-2 px-2">
                <SeverityBadge severity={f.severity || "UNKNOWN"} />
              </td>
              <td className="py-2 px-2 font-mono text-xs">
                {f.cve_id || "—"}
              </td>
              <td className="py-2 px-2">
                <span className="max-w-xs block truncate" title={f.title}>
                  {f.title || "Unnamed"}
                </span>
              </td>
              <td className="py-2 px-2 font-mono text-xs">
                {f.package_name || "—"}
              </td>
              <td className="py-2 px-2 font-mono text-xs">
                {f.package_version || "—"}
              </td>
              <td className="py-2 px-2 text-xs">
                {f.fix_available ? (
                  <span className="text-green-400">{f.fixed_version || "yes"}</span>
                ) : (
                  <span className="text-gray-600">none</span>
                )}
              </td>
              <td className="py-2 px-2 text-xs text-gray-500 font-mono">
                {new Date(f.first_seen).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ScanTimeline({ scans }: { scans: any[] }) {
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        No scan history yet.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {scans.slice(0, 20).map((scan) => {
        const ok = scan.status === "completed";
        return (
          <div key={scan.id} className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${ok ? "bg-green-500" : "bg-red-500"}`} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">
                {scan.scan_id}
              </p>
              <p className="text-xs text-gray-500 font-mono">
                {new Date(scan.started_at).toLocaleString()}
                {scan.duration_seconds && ` · ${scan.duration_seconds}s`}
              </p>
            </div>
            <div className="flex gap-2 text-xs font-mono">
              <span className="text-red-400">{scan.critical_count}C</span>
              <span className="text-orange-400">{scan.high_count}H</span>
              <span className="text-yellow-400">{scan.medium_count}M</span>
              <span className="text-blue-400">{scan.low_count}L</span>
            </div>
            {scan.total_findings != null && (
              <span className="text-xs text-gray-400 shrink-0">
                {scan.total_findings} findings
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function LoadingState() {
  return (
    <div className="flex items-center justify-center py-24">
      <div className="text-gray-500">Loading...</div>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="bg-red-950/50 border border-red-900 rounded-lg p-6 text-center">
      <p className="text-red-400 font-medium">Error loading data</p>
      <p className="text-red-300/60 text-sm mt-1">{message}</p>
    </div>
  );
}
