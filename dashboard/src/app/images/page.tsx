"use client";

import Link from "next/link";
import { AlertTriangle, CircleSlash2, Container, HardDrive, Package, RefreshCw, ShieldAlert } from "lucide-react";
import { useCallback, useState } from "react";
import { useAsync } from "@/hooks/useAsync";
import Layout from "@/components/Layout";
import EmptyState from "@/components/EmptyState";
import LoadingSpinner from "@/components/LoadingSpinner";
import RegistryCatalog from "@/components/images/RegistryCatalog";
import type { ImageDetail, Page, RegistryInventory, RegistryTag } from "@/types";
import { formatBytes } from "@/lib/bytes";
import { cx } from "@/lib/cx";

function seenRunning(value: string | null | undefined): string {
  return value ? `Seen running ${new Date(value).toLocaleString()}` : "Seen running";
}

export default function ImagesPage() {
  const [scanning, setScanning] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [runningOnly, setRunningOnly] = useState(false);

  const loadInventory = useCallback(async () => {
    const [imagesResponse, registryResponse] = await Promise.all([
      fetch(`/api/images?limit=100${runningOnly ? "&running=true" : ""}`, { cache: "no-store" }),
      fetch("/api/registry", { cache: "no-store" }),
    ]);
    if (!imagesResponse.ok) throw new Error("Images unavailable");
    const payload = await imagesResponse.json();
    const page: Page<ImageDetail> = Array.isArray(payload)
      ? { items: payload, limit: payload.length, offset: 0, count: payload.length, total: payload.length }
      : payload;
    const registry: RegistryInventory | null = registryResponse.ok ? await registryResponse.json() : null;
    // The shown list says which filter it answers: the checkbox changes at once, the list on arrival.
    return { page, registry, runningOnly };
  }, [runningOnly]);
  const inventory = useAsync(loadInventory);
  const load = inventory.reload;
  const page = inventory.error ? null : (inventory.data?.page ?? null);
  const registry = inventory.error ? null : (inventory.data?.registry ?? null);
  const listedRunningOnly = inventory.data?.runningOnly ?? false;
  const loading = inventory.loading;

  async function scanTag(item: RegistryTag) {
    setScanning(item.image_name);
    setNotice("");
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ image_name: item.image_name, priority: "normal" }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || body.error || "Unable to queue scan");
      setNotice(`Scan queued for ${item.image_name}. The security status will update when the worker finishes.`);
      load();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to queue scan");
    } finally {
      setScanning(null);
    }
  }

  if (loading && !page)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  return (
    <Layout>
      <div className="mb-8 flex items-end justify-between gap-4">
        <div>
          <div className="eyebrow mb-3">Inventory / Registry control room</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Images</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            One place to see what is in the local registry, what Scrutineering has scanned, and which images need
            attention.
          </p>
        </div>
        <button
          onClick={load}
          className={cx(
            "inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2.5 text-sm",
            "text-slate-300 hover:text-white",
          )}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>
      {notice && (
        <div className="mb-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-sm text-cyan-100">
          {notice}
        </div>
      )}
      {registry ? (
        <>
          <section
            className={cx(
              "mb-6 rounded-3xl border border-cyan-400/15 bg-gradient-to-br",
              "from-[#101d2d] to-[#0c131e] p-5 shadow-2xl shadow-cyan-950/10",
              "sm:p-7",
            )}
          >
            <div className="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <div
                  className={cx(
                    "mb-3 flex items-center gap-2",
                    "text-xs font-semibold uppercase tracking-[0.18em]",
                    "text-cyan-300",
                  )}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${registry.registry.reachable ? "bg-emerald-400" : "bg-rose-400"}`}
                  />{" "}
                  Local registry {registry.registry.reachable ? "connected" : "unavailable"}
                </div>
                <h2 className="text-2xl font-semibold text-white">{registry.registry.host}</h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Tags are read directly from the registry and joined with scan findings, scan history, and remediation
                  state.
                </p>
              </div>
              <div className="grid shrink-0 grid-cols-2 gap-3 sm:grid-cols-3">
                <Summary
                  label="Repositories"
                  value={registry.summary.repositories}
                  icon={<Container className="h-4 w-4" />}
                />
                <Summary label="Tags" value={registry.summary.tags} icon={<Package className="h-4 w-4" />} />
                <Summary
                  label="Stored"
                  value={formatBytes(registry.summary.stored_bytes)}
                  icon={<HardDrive className="h-4 w-4" />}
                />
                <Summary
                  label="Issues"
                  value={registry.summary.issues_found}
                  icon={<ShieldAlert className="h-4 w-4" />}
                />
                <Summary
                  label="Unscanned"
                  value={registry.summary.not_scanned}
                  icon={<CircleSlash2 className="h-4 w-4" />}
                />
              </div>
            </div>
          </section>
          <RegistryCatalog inventory={registry} scanning={scanning} onScan={scanTag} onChanged={load} />
        </>
      ) : (
        <div className="mb-8 rounded-2xl border border-amber-400/20 bg-amber-400/5 p-5 text-sm text-amber-100">
          <div className="flex items-center gap-2 font-medium">
            <AlertTriangle className="h-4 w-4" /> Local registry unavailable
          </div>
          <p className="mt-2 text-amber-200/70">
            Start the Compose registry service and refresh. Existing tracked scan results remain available below.
          </p>
        </div>
      )}
      <section className="panel overflow-hidden rounded-2xl">
        <div className="border-b border-slate-800/80 px-5 py-5 sm:px-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow mb-2">Tracked inventory</div>
              <div className="text-sm text-slate-400">
                {page?.total || 0} {listedRunningOnly ? "running " : ""}image{page?.total === 1 ? "" : "s"}
                {listedRunningOnly
                  ? " seen by runtime discovery in the last 30 minutes."
                  : " currently under management."}
              </div>
            </div>
            <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={runningOnly}
                onChange={(event) => setRunningOnly(event.target.checked)}
                className="accent-emerald-400"
              />
              Running only
            </label>
          </div>
        </div>
        <div className="divide-y divide-slate-800/70">
          {page?.items.map((image) => {
            const localFixture = image.repo_name.startsWith("local/");
            const displayName = image.name;
            return (
              <Link
                href={`/images/${image.id}`}
                key={image.id}
                className="flex flex-col gap-4 p-5 transition hover:bg-slate-800/30 sm:flex-row sm:items-center sm:px-6"
              >
                <div className="flex min-w-0 flex-1 items-center gap-4">
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
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="truncate font-mono text-sm text-slate-200">{displayName}</div>
                      {image.running && (
                        <span
                          title={seenRunning(image.last_seen_running_at)}
                          className={cx(
                            "rounded-full bg-emerald-400/10 px-2 py-0.5",
                            "text-[10px] font-semibold uppercase tracking-wider",
                            "text-emerald-200",
                          )}
                        >
                          running
                        </span>
                      )}
                      {(image.containers ?? 0) > 0 && (
                        <span
                          title="Containers runtime discovery listed in the last 30 minutes"
                          className={cx("text-[11px]", image.stale_containers ? "text-amber-200" : "text-slate-400")}
                        >
                          {image.containers} container{image.containers === 1 ? "" : "s"}
                          {image.stale_containers ? ` · ${image.stale_containers} stale` : ""}
                        </span>
                      )}
                      {localFixture && (
                        <span
                          className={cx(
                            "rounded-full bg-violet-400/10 px-2 py-0.5",
                            "text-[10px] font-semibold uppercase tracking-wider",
                            "text-violet-200",
                          )}
                        >
                          local fixture
                        </span>
                      )}
                    </div>
                    <div className="mt-1 text-xs text-slate-600">
                      Last scanned {image.last_scan_at ? new Date(image.last_scan_at).toLocaleString() : "never"}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-5 text-right">
                  <div>
                    <div className="text-lg font-semibold text-slate-200">{image.open_findings}</div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-600">open</div>
                  </div>
                  <div>
                    <div className="text-lg font-semibold text-emerald-300">{image.resolved_findings || 0}</div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-600">resolved</div>
                  </div>
                </div>
              </Link>
            );
          })}
          {!page?.items.length && (
            <EmptyState
              icon={Package}
              title="No images tracked"
              description="Run a scan to populate the managed image inventory."
            />
          )}
        </div>
      </section>
    </Layout>
  );
}

function Summary({ label, value, icon }: { label: string; value: number | string; icon: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-700/70 bg-slate-950/35 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-3 text-sm text-slate-500">
        {label}
        <span className="text-cyan-300">{icon}</span>
      </div>
      <div className="whitespace-nowrap text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}
