import { dashboardResponse } from "../../_lib/backend";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dashboardResponse(`/api/dashboard/findings/${encodeURIComponent(id)}`, undefined, req);
}
