type Preview = {
  source_connected: boolean;
  actionable_finding_ids: number[];
  manual: { finding_id: number; reason: string }[];
};

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

async function readDetail(response: Response): Promise<string> {
  const body = await response.json().catch(() => ({}));
  const detail = body.detail;
  if (typeof detail === "string") return detail;
  if (detail?.code === "finding_already_in_remediation") {
    return `Those findings are already in remediation #${detail.remediation_ids?.join(", #") || "another"}.`;
  }
  if (detail?.reason) return detail.reason;
  if (Array.isArray(detail) && detail[0]?.msg) return `Request rejected: ${detail[0].msg}.`;
  return "Unable to create a remediation proposal.";
}

/**
 * Ask the server how the findings would be fixed, then propose the ones it can fix.
 * Returns a notice for the operator; the server decides what is actionable.
 */
export async function proposeFixes(imageId: number, findingIds: number[]): Promise<string> {
  const request = { image_id: imageId, finding_ids: findingIds };
  const previewResponse = await fetch("/api/remediations/preview", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!previewResponse.ok) return readDetail(previewResponse);
  const preview: Preview = await previewResponse.json();
  if (!preview.source_connected) {
    return "Connect this image's source repository (on the image page) before proposing fixes.";
  }
  if (!preview.actionable_finding_ids.length) {
    return `None of the selected findings can be fixed automatically (${plural(preview.manual.length, "finding")}).`;
  }
  const response = await fetch("/api/remediations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ image_id: imageId, finding_ids: preview.actionable_finding_ids }),
  });
  if (!response.ok) return readDetail(response);
  const remediation = await response.json();
  const skipped = preview.manual.length ? `; ${plural(preview.manual.length, "finding")} need a manual fix` : "";
  const proposed = plural(preview.actionable_finding_ids.length, "finding");
  return `Remediation #${remediation.id} proposed for ${proposed}${skipped}.`;
}
