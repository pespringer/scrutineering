"use client";

import { useState, useEffect, useCallback } from "react";
import { useAsync } from "@/hooks/useAsync";
import { useParams, useSearchParams } from "next/navigation";
import Layout from "@/components/Layout";
import FindingsTable from "@/components/FindingsTable";
import SourcePanel from "@/components/images/SourcePanel";
import { proposeFixes } from "@/lib/remediation";
import SeverityBadge from "@/components/SeverityBadge";
import LoadingSpinner from "@/components/LoadingSpinner";
import EmptyState from "@/components/EmptyState";
import type { ImageDetail, VulnerabilityFinding } from "@/types";
import { Package, ArrowLeft, Filter, Check, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { cx } from "@/lib/cx";

const SEVERITY_OPTIONS = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

type ImageDetailData = { image: ImageDetail | null; findings: VulnerabilityFinding[]; total: number };

export default function ImageDetailPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const imageId = params.id as string;
  const initialSeverity = searchParams.get("severity") || "all";

  const [severityFilter, setSeverityFilter] = useState(initialSeverity);
  const [findingsOffset, setFindingsOffset] = useState(0);
  const [selectedFindings, setSelectedFindings] = useState<number[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [canRemediate, setCanRemediate] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [proposedId, setProposedId] = useState<number | null>(null);
  const FINDINGS_PAGE_SIZE = 25;

  const loadDetail = useCallback(async (): Promise<ImageDetailData> => {
    const imageResponse = await fetch(`/api/images/${imageId}`);
    const imageData = await imageResponse.json();
    const query = new URLSearchParams({ limit: String(FINDINGS_PAGE_SIZE), offset: String(findingsOffset) });
    if (severityFilter !== "all") query.set("severity", severityFilter);
    const findingsResponse = await fetch(`/api/images/${imageId}?${query}`);
    const findingsData = await findingsResponse.json();
    return {
      image: imageData.image || null,
      findings: findingsData.findings || [],
      total: findingsData.findings_page?.total ?? findingsData.findings?.length ?? 0,
    };
  }, [imageId, severityFilter, findingsOffset]);
  const detail = useAsync(loadDetail);
  const loadData = detail.reload;
  const image = detail.data?.image ?? null;
  const findings = detail.data?.findings ?? [];
  const findingsTotal = detail.data?.total ?? 0;
  const loading = detail.loading && !detail.data;

  useEffect(() => {
    fetch("/api/permissions", { cache: "no-store" })
      .then((response) => (response.ok ? response.json() : null))
      .then((permissions) => {
        setCanManage(Boolean(permissions?.can_manage_scans));
        setCanRemediate(Boolean(permissions?.can_remediate));
      })
      .catch(() => undefined);
  }, []);

  async function acknowledgeSelected() {
    if (!selectedFindings.length) return;
    const response = await fetch("/api/findings/bulk-acknowledge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ids: selectedFindings }),
    });
    setNotice(response.ok ? "Selected findings acknowledged." : "Unable to acknowledge findings.");
    if (response.ok) {
      setSelectedFindings([]);
      loadData();
    }
  }

  async function proposeRemediation() {
    if (!selectedFindings.length) return;
    setNotice("Planning fixes…");
    setProposedId(null);
    const proposal = await proposeFixes(Number(imageId), selectedFindings);
    setNotice(proposal.message);
    setProposedId(proposal.remediationId ?? null);
    setSelectedFindings([]);
    loadData();
  }

  const handleSeverityChange = (sev: string) => {
    setSeverityFilter(sev);
    setFindingsOffset(0);
  };

  if (loading)
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  if (!image)
    return (
      <Layout>
        <EmptyState icon={Package} title="Image not found" description="No scan data exists for this image." />
      </Layout>
    );

  return (
    <Layout>
      {/* Breadcrumb */}
      <Link
        href="/images"
        className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-blue-400 transition-colors mb-4"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to images
      </Link>

      {/* Image header */}
      <div className="panel relative mb-6 overflow-hidden rounded-3xl p-6 sm:p-8">
        <div className="flex items-center gap-3 mb-3">
          <div
            className={cx(
              "flex h-11 w-11 items-center",
              "justify-center rounded-xl border border-cyan-300/15",
              "bg-cyan-300/[0.08]",
            )}
          >
            <Package className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h2 className="break-all font-mono text-xl font-semibold tracking-tight text-white sm:text-2xl">
              {image.name}
            </h2>
            {image.last_scan_at && (
              <p className="mt-1 text-xs text-slate-500">
                Last scanned: {new Date(image.last_scan_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>

        {/* Stats row */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-6">
          {[
            { label: "Total Open", value: image.open_findings, color: "text-slate-100" },
            { label: "Critical", value: image.critical_count, color: "text-red-400" },
            { label: "High", value: image.high_count, color: "text-orange-400" },
            { label: "Medium", value: image.medium_count, color: "text-yellow-400" },
            { label: "Low", value: image.low_count, color: "text-slate-400" },
            { label: "Resolved", value: image.resolved_findings || 0, color: "text-emerald-300" },
          ].map((stat) => (
            <div
              key={stat.label}
              className="rounded-xl border border-slate-700/60 bg-slate-950/40 px-3 py-3 text-center"
            >
              <span className={`text-lg font-bold ${stat.color}`}>{stat.value}</span>
              <span className="text-xs text-slate-500 block">{stat.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Severity filter */}
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <Filter className="w-4 h-4 text-slate-500" />
        <span className="text-sm text-slate-400 mr-1">Filter:</span>
        <div className="flex gap-1">
          {SEVERITY_OPTIONS.map((sev) => (
            <button
              key={sev}
              onClick={() => handleSeverityChange(sev)}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                severityFilter === sev
                  ? sev === "CRITICAL"
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : sev === "HIGH"
                      ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                      : sev === "MEDIUM"
                        ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                        : "bg-slate-600/20 text-slate-300 border border-slate-600/30"
                  : "bg-slate-800 text-slate-500 hover:text-slate-300 border border-transparent"
              }`}
            >
              {sev === "all" ? (
                "All"
              ) : (
                <>
                  <SeverityBadge severity={sev} />{" "}
                </>
              )}
              {sev === "all" || sev}
            </button>
          ))}
        </div>
      </div>

      {/* Findings count */}
      <p className="mb-3 text-sm text-slate-500">
        Showing {findingsOffset + (findings.length ? 1 : 0)}–{findingsOffset + findings.length} of {findingsTotal}{" "}
        findings
      </p>

      {/* Findings table */}
      <SourcePanel imageId={image.id} source={image.source} canEdit={canRemediate} onSaved={loadData} />
      {canManage && selectedFindings.length > 0 && (
        <div
          className={cx(
            "mb-4 flex flex-wrap items-center gap-2 rounded-xl",
            "border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-xs",
            "text-cyan-200",
          )}
        >
          <span>{selectedFindings.length} selected</span>
          <button
            onClick={proposeRemediation}
            className="inline-flex items-center gap-1 rounded-lg bg-cyan-400 px-2.5 py-1.5 font-semibold text-slate-950"
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Propose remediation
          </button>
          <button
            onClick={acknowledgeSelected}
            className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 px-2.5 py-1.5"
          >
            <Check className="h-3.5 w-3.5" /> Acknowledge
          </button>
          <button onClick={() => setSelectedFindings([])} className="text-slate-400">
            Clear
          </button>
        </div>
      )}
      {notice && (
        <p className="mb-3 text-sm text-cyan-200">
          {notice}
          {proposedId && (
            <Link className="ml-2 underline" href={`/remediations/${proposedId}`}>
              Review and approve it
            </Link>
          )}
        </p>
      )}
      <div className="panel rounded-2xl p-4 sm:p-6">
        <FindingsTable
          findings={findings}
          selectable={canManage}
          selected={selectedFindings}
          onSelect={(id, checked) =>
            setSelectedFindings((current) =>
              checked ? [...new Set([...current, id])] : current.filter((value) => value !== id),
            )
          }
        />
      </div>
      <div className="mt-4 flex justify-end gap-3 text-xs">
        <button
          disabled={findingsOffset === 0}
          onClick={() => setFindingsOffset(Math.max(0, findingsOffset - FINDINGS_PAGE_SIZE))}
          className="text-cyan-300 disabled:text-slate-700"
        >
          Previous
        </button>
        <button
          disabled={findingsOffset + FINDINGS_PAGE_SIZE >= findingsTotal}
          onClick={() => setFindingsOffset(findingsOffset + FINDINGS_PAGE_SIZE)}
          className="text-cyan-300 disabled:text-slate-700"
        >
          Next
        </button>
      </div>
    </Layout>
  );
}
