"use client";

import { useEffect, useState } from "react";

type Publication = { id: number; repository: string; status: string; verification_status: string | null };
type Preview = { publication_id: number; stale: boolean; allowed_actions: string[] };

export default function RecoveryControls({ publications }: { publications: Publication[] }) {
  const [previews, setPreviews] = useState<Record<number, Preview>>({});
  const [busy, setBusy] = useState<number | null>(null);
  useEffect(() => {
    Promise.all(publications.map((publication) => fetch(`/api/remediations/publications/${publication.id}/recovery-preview`, { cache: "no-store" }).then((response) => response.ok ? response.json() : null)))
      .then((items) => setPreviews(Object.fromEntries(items.filter(Boolean).map((item: Preview) => [item.publication_id, item]))));
  }, [publications]);

  async function recover(publication: Publication, action: string) {
    if (!window.confirm(`Record a ${action.replaceAll("_", " ")} request for ${publication.repository}?`)) return;
    setBusy(publication.id);
    try {
      await fetch(`/api/remediations/publications/${publication.id}/recovery`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, idempotency_key: `dashboard-${publication.id}-${action}-${Date.now()}` }) });
      const response = await fetch(`/api/remediations/publications/${publication.id}/recovery-preview`, { cache: "no-store" });
      if (response.ok) {
        const preview = await response.json();
        setPreviews((current) => ({ ...current, [publication.id]: preview }));
      }
    } finally { setBusy(null); }
  }

  return <>{publications.map((publication) => { const preview = previews[publication.id]; if (!preview?.stale) return null; return <div key={publication.id} className="mt-3 rounded-xl border border-amber-400/20 bg-amber-400/5 p-3"><p className="text-xs leading-5 text-slate-400">Stale publication. Recovery requests are audited and do not mutate the provider.</p><div className="mt-2 flex flex-wrap gap-2">{preview.allowed_actions.map((action) => <button key={action} disabled={busy === publication.id} onClick={() => recover(publication, action)} className="rounded-lg border border-slate-700 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-cyan-400/50 hover:text-cyan-200 disabled:opacity-50">{busy === publication.id ? "Saving…" : action.replaceAll("_", " ")}</button>)}</div></div>; })}</>;
}
