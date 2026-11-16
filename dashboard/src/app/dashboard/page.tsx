"use client";

import Link from "next/link";
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Info,
  Package,
  RefreshCw,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import StatCard from "@/components/StatCard";
import LoopSteps from "@/components/dashboard/LoopSteps";
import PostureHero from "@/components/dashboard/PostureHero";
import RecentScans from "@/components/dashboard/RecentScans";
import RiskDistribution from "@/components/dashboard/RiskDistribution";
import SeverityTrendChart from "@/components/dashboard/SeverityTrendChart";
import TrackedImages from "@/components/dashboard/TrackedImages";
import { useDashboardData } from "@/hooks/useDashboardData";
import { cx } from "@/lib/cx";
import { isActiveScan } from "@/lib/status";
import type { DashboardSession } from "@/types";

function greetingFor(session: DashboardSession | null): string {
  const identity = session?.email || session?.subject || "operator";
  const name = identity.includes("@") ? identity.split("@")[0] : identity.split(/[./:_-]/)[0];
  const hour = new Date().getHours();
  return `${hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening"}, ${name}.`;
}

export default function DashboardPage() {
  const { posture, trends, scans, images, session, loading, error, refreshedAt, reload } = useDashboardData();
  const activeScans = scans.filter((scan) => isActiveScan(scan.status));

  if (loading) {
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
          <div className="eyebrow mb-3 flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Security operations
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">{greetingFor(session)}</h1>
          <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
            One view of your container estate, its exposure, and the work that needs attention next.
          </p>
          {refreshedAt && (
            <p className="mt-2 text-xs text-slate-600">
              Data refreshed {refreshedAt.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}
            </p>
          )}
        </div>
        <button
          onClick={reload}
          className={cx(
            "inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900/80",
            "px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white",
          )}
        >
          <RefreshCw className="h-4 w-4" /> Refresh data
        </button>
      </div>

      {error && (
        <div
          className={cx(
            "mb-6 flex items-center gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/[0.07]",
            "px-4 py-3 text-sm text-amber-200",
          )}
        >
          <Info className="h-4 w-4 shrink-0" />
          {error}
          <button onClick={reload} className="ml-auto font-semibold underline underline-offset-4">
            Retry
          </button>
        </div>
      )}

      {activeScans.length > 0 && (
        <section className="mb-6 rounded-2xl border border-cyan-400/20 bg-cyan-400/[0.06] px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-cyan-100">Scan activity in progress</div>
              <p className="mt-1 text-xs text-cyan-200/70">
                {activeScans.length} scan{activeScans.length === 1 ? " is" : "s are"} queued or running. Open Scan
                history to follow the current phase.
              </p>
            </div>
            <Link
              href="/scans"
              className="inline-flex items-center gap-2 text-sm font-semibold text-cyan-200 hover:text-white"
            >
              Follow activity <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      )}

      <LoopSteps />
      <PostureHero posture={posture} />

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 lg:gap-4">
        <StatCard
          label="Images"
          value={posture.total_scanned_images}
          detail="in your estate"
          icon={<Package className="h-4 w-4" />}
          color="blue"
        />
        <StatCard
          label="Open findings"
          value={posture.total_findings}
          detail="across all images"
          icon={<ShieldAlert className="h-4 w-4" />}
        />
        <StatCard
          label="Critical"
          value={posture.critical_count}
          detail="needs immediate action"
          icon={<AlertCircle className="h-4 w-4" />}
          color="red"
        />
        <StatCard
          label="High"
          value={posture.high_count}
          detail="priority exposure"
          icon={<AlertTriangle className="h-4 w-4" />}
          color="orange"
        />
        <StatCard
          label="Fixable"
          value={posture.fixable_count}
          detail="with known upgrades"
          icon={<TrendingUp className="h-4 w-4" />}
          color="green"
        />
        <StatCard
          label="Scan status"
          value={posture.last_scan_status || "—"}
          detail="most recent run"
          icon={<CheckCircle2 className="h-4 w-4" />}
          color="blue"
        />
      </div>

      <div className="mb-6 grid gap-6 xl:grid-cols-[1.45fr_0.85fr]">
        <SeverityTrendChart trends={trends} />
        <RiskDistribution posture={posture} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.9fr_1.6fr]">
        <RecentScans scans={scans} />
        <TrackedImages images={images} />
      </div>
    </Layout>
  );
}
