import { dashboardDownload } from "../../../_lib/backend";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return dashboardDownload(`/api/dashboard/remediations/${encodeURIComponent(id)}/evidence.sig`, request);
}
