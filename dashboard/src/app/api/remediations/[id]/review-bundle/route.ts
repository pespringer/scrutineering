import { dashboardResponse } from "../../../_lib/backend";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dashboardResponse(`/api/dashboard/remediations/${encodeURIComponent(id)}/review-bundle`, undefined, request);
}
