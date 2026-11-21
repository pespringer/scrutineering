"use client";

import { use } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import Layout from "@/components/Layout";
import LoadingSpinner from "@/components/LoadingSpinner";
import EventTimeline from "@/components/remediations/EventTimeline";
import ExecutionControls from "@/components/remediations/ExecutionControls";
import CandidatePanel from "@/components/remediations/CandidatePanel";
import ProposedChanges from "@/components/remediations/ProposedChanges";
import Publications from "@/components/remediations/Publications";
import EvidencePanel from "@/components/remediations/EvidencePanel";
import DeploymentPanel from "@/components/remediations/DeploymentPanel";
import WorkflowStatus from "@/components/remediations/WorkflowStatus";
import { usePermissions } from "@/hooks/usePermissions";
import { useRemediation } from "@/hooks/useRemediation";
import { cx } from "@/lib/cx";
import { statusTone } from "@/lib/status";

export default function RemediationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { remediation, events, loadError, notice, busy, publishing, act } = useRemediation(id);
  const permissions = usePermissions();

  if (loadError && !remediation) {
    return (
      <Layout>
        <Link href="/remediations" className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300">
          <ArrowLeft className="h-4 w-4" /> Back to remediations
        </Link>
        <div className="panel rounded-2xl p-6 text-sm text-amber-200">
          Remediation #{id}: {loadError}
        </div>
      </Layout>
    );
  }
  if (!remediation) {
    return (
      <Layout>
        <LoadingSpinner />
      </Layout>
    );
  }

  const label = remediation.status_label;
  const proposedByViewer = Boolean(
    permissions.separate_approver && remediation.proposed_by && remediation.proposed_by === permissions.subject,
  );
  return (
    <Layout>
      <Link href="/remediations" className="mb-6 inline-flex items-center gap-2 text-sm text-cyan-300">
        <ArrowLeft className="h-4 w-4" /> Back to remediations
      </Link>
      <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="eyebrow mb-3">Remediation #{remediation.id}</div>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Governed fix workflow</h1>
          <p className="mt-2 text-sm text-slate-400">
            <Link href={`/images/${remediation.image_id}`} className="text-cyan-300 hover:text-cyan-200">
              Image {remediation.image_id}
            </Link>{" "}
            · {remediation.finding_count} finding(s) · {label}
          </p>
        </div>
        <div
          className={cx(
            "rounded-full px-4 py-2 text-xs font-semibold uppercase tracking-wider",
            statusTone(remediation.status),
          )}
        >
          {label}
        </div>
      </div>
      {notice && (
        <div className="mb-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-4 text-sm text-cyan-100">
          {notice}
        </div>
      )}
      <WorkflowStatus remediation={remediation} />
      <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
        <section className="space-y-6">
          <ExecutionControls
            remediation={remediation}
            busy={busy}
            publishing={publishing}
            proposedByViewer={proposedByViewer}
            onAction={act}
          />
          <ProposedChanges actions={remediation.actions} />
          <CandidatePanel remediation={remediation} />
          <EventTimeline events={events} />
        </section>
        <aside className="space-y-6">
          <DeploymentPanel imageId={remediation.image_id} deployment={remediation.deployment} />
          <Publications publications={remediation.publications} />
          <EvidencePanel id={remediation.id} evidence={remediation.evidence} />
        </aside>
      </div>
    </Layout>
  );
}
