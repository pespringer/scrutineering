"use client";

import Link from "next/link";
import { use, useCallback } from "react";
import { ArrowLeft, FileDown, KeyRound, ShieldCheck } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import { useAsync } from "@/hooks/useAsync";
import { getJson } from "@/lib/http";
import type { ReportDetail, ReportDocument } from "@/types";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const LINK = "inline-flex items-center gap-1.5 text-xs text-cyan-300 underline-offset-2 hover:underline";

function day(value: string): string {
  return new Date(value).toLocaleDateString(undefined, { timeZone: "UTC" });
}

function Section({ title, note, children }: { title: string; note?: string; children: React.ReactNode }) {
  return (
    <section className="panel rounded-2xl p-5 sm:p-6 print:break-inside-avoid">
      <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
      {note && <p className="mt-1 text-xs text-slate-500">{note}</p>}
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Stat({ label, value, tone = "text-slate-100" }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border border-slate-700/60 bg-slate-950/40 px-3 py-3 text-center">
      <div className={`text-lg font-bold ${tone}`}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}

function ChangeTable({ changes }: { changes: ReportDocument["changes"] }) {
  const rows = [
    ["New", changes.new],
    ["Resolved", changes.resolved],
    ["Reopened", changes.reopened],
  ] as const;
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase tracking-wider text-slate-500">
        <tr>
          <th className="py-1 font-medium">Findings</th>
          {SEVERITIES.map((severity) => (
            <th key={severity} className="py-1 text-right font-medium capitalize">
              {severity}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="text-slate-300">
        {rows.map(([label, counts]) => (
          <tr key={label} className="border-t border-slate-800/70">
            <td className="py-2">{label}</td>
            {SEVERITIES.map((severity) => (
              <td key={severity} className="py-2 text-right tabular-nums">
                {counts[severity]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ReportBody({ document }: { document: ReportDocument }) {
  const { posture, scans, remediations, deployments, top_images: topImages } = document;
  const generated = new Date(document.period.generated_at).toLocaleString();
  return (
    <div className="space-y-6">
      <Section title="Posture" note={`As of ${generated}.`}>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-6">
          <Stat label="Critical" value={posture.open.critical} tone="text-red-400" />
          <Stat label="High" value={posture.open.high} tone="text-orange-400" />
          <Stat label="Medium" value={posture.open.medium} tone="text-yellow-400" />
          <Stat label="Low" value={posture.open.low} tone="text-slate-400" />
          <Stat label="Fixable" value={posture.fixable} tone="text-emerald-300" />
          <Stat label="Images" value={posture.active_images} />
        </div>
        <p className="mt-3 text-xs text-slate-500">{posture.running_images} image(s) seen running.</p>
      </Section>
      <Section title="This period">
        <ChangeTable changes={document.changes} />
        <p className="mt-4 text-xs text-slate-400">
          Scans:{" "}
          {Object.entries(scans.by_status)
            .map(([status, count]) => `${count} ${status}`)
            .join(", ") || "none"}
          . {scans.images_not_scanned} active image(s) weren&apos;t scanned.
        </p>
      </Section>
      <Section title="Fixes" note="Remediations that completed or failed in the period.">
        {remediations.length ? (
          <ul className="divide-y divide-slate-800/70 text-sm">
            {remediations.map((item) => (
              <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <Link href={`/remediations/${item.id}`} className="text-cyan-300 hover:text-cyan-200">
                  #{item.id} · <span className="font-mono">{item.image}</span>
                </Link>
                <span className={item.outcome === "completed" ? "text-emerald-300" : "text-amber-200"}>
                  {item.outcome}
                  {item.evidence_sha256 ? " · evidence signed" : ""}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-slate-500">None.</p>
        )}
      </Section>
      <Section title="Containers on an older build" note={`As of ${generated}.`}>
        {deployments.stale_containers.length ? (
          <ul className="space-y-1 text-sm text-slate-300">
            {deployments.stale_containers.map((item) => (
              <li key={`${item.container}-${item.image}`}>
                <span className="font-mono">{item.container}</span>{" "}
                <span className="text-slate-500">({item.image})</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-slate-500">None of {deployments.containers} running container(s).</p>
        )}
        {deployments.fixes_not_running.length > 0 && (
          <p className="mt-3 text-xs text-amber-200">
            Fixes not running everywhere yet:{" "}
            {deployments.fixes_not_running
              .map((fix) => `#${fix.remediation_id} (${fix.fixed} of ${fix.containers})`)
              .join(", ")}
          </p>
        )}
      </Section>
      <Section title="Most critical and high findings" note={`Open, as of ${generated}.`}>
        {topImages.length ? (
          <ol className="space-y-1 text-sm">
            {topImages.map((item) => (
              <li key={item.image_id} className="flex justify-between gap-3">
                <Link href={`/images/${item.image_id}`} className="font-mono text-slate-300 hover:text-cyan-300">
                  {item.image}
                </Link>
                <span className="tabular-nums text-slate-400">
                  <span className="text-red-400">{item.critical}</span> /{" "}
                  <span className="text-orange-400">{item.high}</span>
                </span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-xs text-slate-500">No open critical or high findings.</p>
        )}
      </Section>
    </div>
  );
}

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const load = useCallback(() => getJson<ReportDetail>(`/api/reports/${encodeURIComponent(id)}`), [id]);
  const report = useAsync(load);
  const data = report.data;
  const fingerprint = data?.key_id?.replace(/^sha256:/, "");
  return (
    <Layout>
      <Link href="/reports" className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300 print:hidden">
        <ArrowLeft className="h-4 w-4" /> Back to reports
      </Link>
      {report.error && !data && (
        <p className="text-sm text-amber-200">
          Report #{id}: {report.error}
        </p>
      )}
      {!data && !report.error && <LoadingSpinner />}
      {data && (
        <>
          <div className="mb-6">
            <div className="eyebrow mb-3">{data.kind === "weekly" ? "Weekly report" : "On-demand report"}</div>
            <h1 className="text-3xl font-semibold tracking-tight text-white">
              {day(data.period_start)} – {day(data.period_end)}
            </h1>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 print:hidden">
              <a
                href={`/api/reports/${data.id}/report.json`}
                download
                title={`SHA-256 ${data.sha256}`}
                className={LINK}
              >
                <FileDown className="h-3.5 w-3.5" /> report.json
              </a>
              {data.signed && fingerprint ? (
                <>
                  <a href={`/api/reports/${data.id}/report.json.sig`} download className={LINK}>
                    <ShieldCheck className="h-3.5 w-3.5" /> signature
                  </a>
                  <a href={`/api/signing-keys/${fingerprint}.pem`} download className={LINK}>
                    <KeyRound className="h-3.5 w-3.5" /> public key
                  </a>
                </>
              ) : (
                <span className="text-xs text-slate-500">unsigned</span>
              )}
            </div>
          </div>
          <ReportBody document={data.document} />
        </>
      )}
    </Layout>
  );
}
