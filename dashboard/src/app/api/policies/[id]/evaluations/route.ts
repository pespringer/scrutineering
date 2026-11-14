import { dashboardResponse } from "../../../_lib/backend";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const query = new URL(request.url).search;
  return dashboardResponse(`/api/dashboard/policies/${id}/evaluations${query}`, undefined, request);
}
