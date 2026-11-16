"use client";

import { useCallback, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import Pagination from "@/components/Pagination";
import BulkScanActions from "@/components/scans/BulkScanActions";
import ScanFilters from "@/components/scans/ScanFilters";
import ScanForm from "@/components/scans/ScanForm";
import ScanRow from "@/components/scans/ScanRow";
import { usePermissions } from "@/hooks/usePermissions";
import { useScanHistory } from "@/hooks/useScanHistory";
import { useScanWatcher } from "@/hooks/useScanWatcher";
import { cx } from "@/lib/cx";
import { postJson } from "@/lib/http";
import { isActiveScan } from "@/lib/status";
import type { ScanResult } from "@/types";

const PAGE_SIZE = 20;

export default function ScansPage() {
  const history = useScanHistory(PAGE_SIZE);
  const permissions = usePermissions();
  const [notice, setNotice] = useState<string | null>(null);
  const [watchedScanId, setWatchedScanId] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const { reload } = history;

  const onScanFinished = useCallback(
    (scan: ScanResult) => {
      setWatchedScanId(null);
      setNotice(`Scan of ${scan.image_name} ${scan.status}.`);
      reload();
    },
    [reload],
  );
  useScanWatcher(watchedScanId, onScanFinished);

  async function cancelScan(scanId: string) {
    try {
      await postJson(`/api/scans/${scanId}`);
      setNotice("Scan cancellation requested.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to cancel scan.");
    }
    reload();
  }

  const scans = history.page?.items || [];
  const counts = {
    completed: scans.filter((s) => s.status === "completed").length,
    running: scans.filter((s) => isActiveScan(s.status)).length,
    failed: scans.filter((s) => s.status === "failed" || s.status === "partial").length,
  };

  const healthSummary = history.health
    ? `Live scan health: ${Math.round(history.health.terminal_rate * 100)}% terminal across ` +
      `${history.health.total} recent scans` +
      (history.health.degraded ? " · degraded or failed scans require review." : " · healthy.")
    : "";

  if (history.loading && !history.page) {
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div>
          <div className="eyebrow mb-3">Operations / Scan history</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Scan history</h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Review every scan and launch a targeted image check without leaving the control plane.
          </p>
        </div>
        <button
          onClick={reload}
          className={cx(
            "inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80",
            "px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white",
          )}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {permissions.can_manage_scans ? (
        <ScanForm
          onQueued={(scan) => {
            setWatchedScanId(scan.scan_id);
            history.setOffset(0);
            reload();
          }}
        />
      ) : (
        <div className="panel mb-6 rounded-2xl p-5 text-sm text-slate-400">
          Your role can review scan history but cannot start or cancel scans.
        </div>
      )}
      {notice && <p className="mb-6 text-sm text-cyan-200">{notice}</p>}

      <div className="mb-6 grid grid-cols-3 gap-3">
        <MiniStat label="Completed" value={counts.completed} color="text-emerald-300" />
        <MiniStat label="In flight" value={counts.running} color="text-cyan-300" />
        <MiniStat label="Failed or partial" value={counts.failed} color="text-rose-300" />
      </div>

      {history.health && (
        <div
          className={cx(
            "mb-6 rounded-2xl border px-5 py-4 text-sm",
            history.health.degraded
              ? "border-amber-400/20 bg-amber-400/5 text-amber-200"
              : "border-emerald-400/20 bg-emerald-400/5 text-emerald-200",
          )}
        >
          {healthSummary}
        </div>
      )}
      {history.failed && (
        <div className="mb-6 rounded-2xl border border-amber-400/20 bg-amber-400/5 px-5 py-4 text-sm text-amber-200">
          Scan history is unavailable right now. Try refreshing in a moment.
        </div>
      )}

      <section className="panel overflow-hidden rounded-2xl">
        <ScanFilters
          search={history.search}
          filter={history.filter}
          onSearch={history.setSearch}
          onFilter={history.setFilter}
        />
        {permissions.can_manage_scans && selected.length > 0 && (
          <BulkScanActions
            selected={selected}
            onDone={(message) => {
              setSelected([]);
              setNotice(message);
              reload();
            }}
          />
        )}
        <div className="divide-y divide-slate-800/70">
          {scans.map((scan) => (
            <ScanRow
              key={scan.scan_id}
              scan={scan}
              canCancel={Boolean(permissions.can_cancel_scans)}
              selected={selected.includes(scan.scan_id)}
              onSelect={(checked) =>
                setSelected((current) =>
                  checked ? [...new Set([...current, scan.scan_id])] : current.filter((id) => id !== scan.scan_id),
                )
              }
              onCancel={() => cancelScan(scan.scan_id)}
            />
          ))}
        </div>
        {!scans.length && (
          <EmptyState
            icon={Search}
            title="No matching scans"
            description={
              history.search
                ? "Try a different repository or clear the search."
                : "No scan history exists for this filter."
            }
          />
        )}
      </section>
      <Pagination
        offset={history.page?.offset || 0}
        count={scans.length}
        total={history.page?.total || 0}
        pageSize={PAGE_SIZE}
        noun="scans"
        onChange={history.setOffset}
      />
    </Layout>
  );
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="panel rounded-2xl p-4 sm:p-5">
      <div className="eyebrow mb-3">{label}</div>
      <div className={`text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}
