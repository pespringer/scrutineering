import { dashboardDownload } from "../../../_lib/backend";

/** The report's bytes exactly as signed. */
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return dashboardDownload(`/api/dashboard/reports/${encodeURIComponent(id)}.json`, request);
}
