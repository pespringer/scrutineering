import { dashboardResponse } from "../../_lib/backend";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const query = new URL(req.url).search;
  return dashboardResponse(`/api/dashboard/images/${id}${query}`, undefined, req);
}
